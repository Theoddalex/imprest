"""The policy engine — the core of agentmandate.

This is deliberately PURE: it has no knowledge of web3, MCP, files, or the
network. It takes (a request, the spend history, the current time) and returns
a verdict. That purity is why it can be exhaustively unit-tested — and the code
guarding money is exactly the code that must be provably correct.

Rules are evaluated in priority order; the FIRST one that fails wins, so the
returned reason always names the specific guardrail that stopped the payment.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

import yaml

from agentmandate.schemas.schemas import (
    AllowanceRecord,
    AssetLimits,
    Decision,
    PaymentRequest,
    Policy,
    PolicyDecision,
    SpendRecord,
)


def _asset_limits_from_dict(raw: dict) -> AssetLimits:
    outstanding = raw.get("max_outstanding_allowance")
    return AssetLimits(
        per_transaction_max=Decimal(str(raw["per_transaction_max"])),
        daily_max=Decimal(str(raw["daily_max"])),
        hourly_max=Decimal(str(raw["hourly_max"])),
        approval_threshold=Decimal(str(raw["approval_threshold"])),
        max_outstanding_allowance=(
            Decimal(str(outstanding)) if outstanding is not None else None
        ),
    )


def _policy_from_dict(raw: dict) -> Policy:
    unknown = str(raw.get("unknown_recipient", "deny")).lower()
    if unknown not in ("deny", "ask"):
        # Fail closed at load time: a typo here must not silently become "deny
        # forever" or, worse, be interpreted loosely later.
        raise ValueError(
            f"unknown_recipient must be 'deny' or 'ask', got {unknown!r}"
        )
    return Policy(
        per_transaction_max=Decimal(str(raw["per_transaction_max"])),
        daily_max=Decimal(str(raw["daily_max"])),
        hourly_max=Decimal(str(raw["hourly_max"])),
        rate_limit_per_minute=int(raw["rate_limit_per_minute"]),
        approval_threshold=Decimal(str(raw["approval_threshold"])),
        allowlist=[a.lower() for a in raw.get("allowlist", [])],
        denylist=[a.lower() for a in raw.get("denylist", [])],
        unknown_recipient=unknown,
        assets={
            symbol: _asset_limits_from_dict(limits)
            for symbol, limits in (raw.get("assets") or {}).items()
        },
    )


def load_policy(path: str) -> Policy:
    """Read a flat policy.yaml into a single Policy (the pre-identity format)."""
    with open(path) as f:
        raw = yaml.safe_load(f) or {}
    return _policy_from_dict(raw)


class PolicyStore:
    """Per-agent policies with a default fallback.

    policy.yaml, identity-aware format:

        default:
          per_transaction_max: 0.05
          ...
        agents:
          support-bot:            # overrides only what differs from default
            per_transaction_max: 0.01

    A flat file (no `default:` key) is treated as the default for every agent,
    so existing configs keep working unchanged.
    """

    def __init__(self, default: dict, agents: dict[str, dict]) -> None:
        self._default = default
        self._agents = agents

    @classmethod
    def load(cls, path: str) -> "PolicyStore":
        with open(path) as f:
            raw = yaml.safe_load(f) or {}
        if "default" in raw:
            return cls(raw["default"], raw.get("agents") or {})
        return cls(raw, {})  # flat legacy format

    def for_agent(self, agent_id: str) -> Policy:
        override = self._agents.get(agent_id, {})
        merged = dict(self._default)
        merged.update(override)
        # `assets` is a nested map — merge per-symbol so an agent can tighten one
        # token's limits without dropping the others it inherits from default.
        merged["assets"] = {
            **(self._default.get("assets") or {}),
            **(override.get("assets") or {}),
        }
        return _policy_from_dict(merged)


class PolicyEngine:
    """Evaluates payment requests against a Policy.

    The engine is stateless: callers pass in the spend `history`. That keeps it
    pure and lets storage (SQLite, memory, whatever) live entirely elsewhere.
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def evaluate(
        self,
        request: PaymentRequest,
        history: list[SpendRecord],
        now: datetime,
        allowances: list[AllowanceRecord] | None = None,
    ) -> PolicyDecision:
        """Judge a request against the policy.

        `history` is the budget-window spend record (rolling caps); `allowances`
        is the ledger of LIVE token allowances this agent has granted — needed
        only for operation='approve', where the standing-liability cap applies.
        """
        p = self.policy
        recipient = request.recipient.lower()
        amount = request.amount
        asset = request.asset
        is_approve = request.operation == "approve"

        # 1. Denylist — absolute, overrides everything else.
        if recipient in p.denylist:
            return PolicyDecision(
                Decision.DENY, f"recipient {request.recipient} is denylisted", "denylist"
            )

        # 2. Allowlist — if configured, recipient must be on it. With
        #    unknown_recipient="ask", a miss is NOT an instant deny: the
        #    request keeps running the gauntlet below (any hard-limit breach
        #    still denies) and, only if it survives them all, lands in the
        #    approval queue for a human to rule on (rule 10).
        unknown = bool(p.allowlist) and recipient not in p.allowlist
        if unknown and p.unknown_recipient != "ask":
            return PolicyDecision(
                Decision.DENY,
                f"recipient {request.recipient} is not on the allowlist",
                "allowlist",
            )

        # 3. Sanity: no zero/negative payments. Exception: approve(spender, 0)
        #    is the standard ERC-20 REVOKE — it reduces risk, so it is allowed.
        if amount < 0 or (amount == 0 and not is_approve):
            return PolicyDecision(
                Decision.DENY, f"amount {amount} must be positive", "amount_positive"
            )

        # 4. Token allowlist — an asset is payable only if it has limits. The
        #    assets map (plus native ETH) IS the allowlist; anything else is a
        #    token the operator never authorised.
        limits = p.limits_for(asset)
        if limits is None:
            return PolicyDecision(
                Decision.DENY,
                f"asset {asset} is not permitted by policy",
                "asset_not_allowed",
            )

        # Budget caps compare like-for-like: only this asset's own history counts
        # (50 USDC must never eat into an ETH ceiling, and vice versa).
        asset_history = [r for r in history if r.asset == asset]

        # 5. Per-transaction cap.
        if amount > limits.per_transaction_max:
            return PolicyDecision(
                Decision.DENY,
                f"amount {amount} {asset} exceeds per-transaction max "
                f"{limits.per_transaction_max}",
                "per_transaction_max",
            )

        # 6. Outstanding-allowance cap (approve only). Budgets reset with their
        #    window; an allowance does NOT — it stays live until spent or
        #    revoked, so across days an agent could stack live allowances far
        #    beyond any one window's budget. This caps the TOTAL an agent has
        #    live at once. approve() overwrites, so this spender's previous
        #    grant is REPLACED by (not added to) the new amount; approving 0
        #    (revoke) always passes and frees the cap.
        if is_approve:
            others = sum(
                (a.amount for a in (allowances or [])
                 if a.asset == asset and a.spender.lower() != recipient),
                start=Decimal(0),
            )
            cap = limits.outstanding_allowance_cap
            if others + amount > cap:
                return PolicyDecision(
                    Decision.DENY,
                    f"total live {asset} allowances {others}+{amount} would "
                    f"exceed the outstanding cap {cap}",
                    "max_outstanding_allowance",
                )

        # 7. Rolling 1-hour spend cap.
        hour_spent = self._spent_since(asset_history, now - timedelta(hours=1))
        if hour_spent + amount > limits.hourly_max:
            return PolicyDecision(
                Decision.DENY,
                f"hourly {asset} spend {hour_spent}+{amount} would exceed "
                f"{limits.hourly_max}",
                "hourly_max",
            )

        # 8. Rolling 24-hour spend cap.
        day_spent = self._spent_since(asset_history, now - timedelta(hours=24))
        if day_spent + amount > limits.daily_max:
            return PolicyDecision(
                Decision.DENY,
                f"daily {asset} spend {day_spent}+{amount} would exceed "
                f"{limits.daily_max}",
                "daily_max",
            )

        # 9. Rate limit — count ALL payments in the last 60 seconds, any asset.
        #    (A flood is a flood regardless of which token it moves.)
        recent = self._count_since(history, now - timedelta(seconds=60))
        if recent >= p.rate_limit_per_minute:
            return PolicyDecision(
                Decision.DENY,
                f"rate limit: {recent} payments in the last minute "
                f"(max {p.rate_limit_per_minute})",
                "rate_limit_per_minute",
            )

        # 10. Unknown recipient in "ask" mode — it survived every hard limit,
        #     so a human decides. Checked before the amount threshold: an
        #     off-list recipient always needs a ruling, however small the sum.
        if unknown:
            return PolicyDecision(
                Decision.NEEDS_APPROVAL,
                f"recipient {request.recipient} is not on the allowlist; "
                "human confirmation required",
                "allowlist_unknown_recipient",
            )

        # 11. Above the approval threshold → allowed, but a human must confirm.
        if amount > limits.approval_threshold:
            return PolicyDecision(
                Decision.NEEDS_APPROVAL,
                f"amount {amount} {asset} exceeds approval threshold "
                f"{limits.approval_threshold}; human confirmation required",
                "approval_threshold",
            )

        # 12. All checks passed.
        return PolicyDecision(Decision.ALLOW, "within policy", "ok")

    @staticmethod
    def _spent_since(history: list[SpendRecord], cutoff: datetime) -> Decimal:
        """Total amount spent at or after `cutoff`."""
        return sum(
            (r.amount for r in history if r.timestamp >= cutoff), start=Decimal(0)
        )

    @staticmethod
    def _count_since(history: list[SpendRecord], cutoff: datetime) -> int:
        """Number of payments at or after `cutoff`."""
        return sum(1 for r in history if r.timestamp >= cutoff)
