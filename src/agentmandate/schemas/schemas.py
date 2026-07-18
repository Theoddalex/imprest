"""Contracts shared across the whole service.

Everything the policy engine, the chain layer, and the MCP tools pass around
is defined here. Amounts are Decimal, never float — money math with floats
silently loses precision, which is unacceptable when the number is ETH.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from enum import Enum


class Decision(str, Enum):
    """Outcome of a policy check."""

    ALLOW = "allow"                    # execute immediately
    DENY = "deny"                      # blocked outright
    NEEDS_APPROVAL = "needs_approval"  # allowed, but a human must confirm first


@dataclass(frozen=True)
class PaymentRequest:
    """What an agent asks to do. Immutable — the engine never mutates the ask."""

    agent_id: str
    recipient: str          # 0x… address (the payee, or the spender for an approval)
    amount: Decimal         # in whole units of `asset` (e.g. 0.05 ETH, 50 USDC)
    reason: str = ""        # free-text: what the payment is for (for the audit log)
    asset: str = "ETH"      # "ETH" (native) or a token symbol, e.g. "USDC"
    operation: str = "transfer"  # "transfer" (move funds) or "approve" (grant allowance)


@dataclass(frozen=True)
class SpendRecord:
    """A payment that was previously approved — the history the engine reasons over."""

    recipient: str
    amount: Decimal
    timestamp: datetime
    asset: str = "ETH"


@dataclass(frozen=True)
class AllowanceRecord:
    """A live ERC-20 allowance this agent has granted — a standing liability.

    Unlike a SpendRecord, an allowance does not expire with a budget window:
    the spender can pull the funds at any point until it is spent or revoked.
    Because ERC-20 approve() OVERWRITES (never adds), the live allowance to a
    spender is simply the amount of the most recent successful approve to them.
    """

    spender: str
    amount: Decimal
    asset: str


@dataclass(frozen=True)
class PolicyDecision:
    """The engine's verdict. `reason` is human-readable and goes to the agent + audit log."""

    decision: Decision
    reason: str
    # which rule fired, e.g. "per_transaction_max" — handy for logs/metrics
    rule: str = ""

    @property
    def allowed(self) -> bool:
        """True if the payment may proceed at all (immediately OR after approval)."""
        return self.decision in (Decision.ALLOW, Decision.NEEDS_APPROVAL)


@dataclass(frozen=True)
class AssetLimits:
    """The amount-based guardrails for one asset (ETH or a token).

    Recipient allow/deny lists and the rate limit are asset-independent and live
    on Policy; these four caps are per-asset because you cannot compare 50 USDC
    against a 0.05 ETH ceiling.
    """

    per_transaction_max: Decimal
    daily_max: Decimal
    hourly_max: Decimal
    approval_threshold: Decimal
    # Cap on the SUM of live allowances across all spenders for this asset.
    # Budgets reset every window, but an allowance is a standing grant that
    # outlives them — without this cap an agent could accumulate live
    # allowances across days beyond any single-window budget. None means
    # "not configured": the daily budget is used as the cap (safe default).
    max_outstanding_allowance: Decimal | None = None

    @property
    def outstanding_allowance_cap(self) -> Decimal:
        """The effective cap on total live allowances (falls back to daily_max)."""
        if self.max_outstanding_allowance is not None:
            return self.max_outstanding_allowance
        return self.daily_max


@dataclass
class Policy:
    """The spend policy — this is the product's config, not code.

    Loaded from policy.yaml. Every field is a guardrail the agent cannot override.

    The flat `*_max`/`approval_threshold` fields are the limits for native ETH.
    Token limits live in `assets` (symbol -> AssetLimits); a token with no entry
    is not payable at all — the map doubles as the token allowlist.
    """

    per_transaction_max: Decimal          # reject any single ETH payment above this
    daily_max: Decimal                    # reject if rolling-24h ETH total would exceed this
    hourly_max: Decimal                   # reject if rolling-1h ETH total would exceed this
    rate_limit_per_minute: int            # max number of payments in any 60s window (all assets)
    approval_threshold: Decimal           # ETH payments above this need human approval
    allowlist: list[str] = field(default_factory=list)  # if non-empty, ONLY these recipients
    denylist: list[str] = field(default_factory=list)   # never pay these, overrides everything
    # What an allowlist MISS means: "deny" blocks outright; "ask" routes the
    # request to the human approval queue instead — but only after every other
    # limit (denylist, caps, budgets, rate) has passed. Irrelevant when the
    # allowlist is empty.
    unknown_recipient: str = "deny"
    assets: dict[str, AssetLimits] = field(default_factory=dict)  # per-token limits

    def limits_for(self, asset: str) -> AssetLimits | None:
        """The amount caps for `asset`, or None if the asset is not payable."""
        if asset == "ETH":
            return AssetLimits(
                self.per_transaction_max,
                self.daily_max,
                self.hourly_max,
                self.approval_threshold,
            )
        return self.assets.get(asset)
