"""The policy engine — the core of agentpay.

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

from agentpay.schemas.schemas import (
    Decision,
    PaymentRequest,
    Policy,
    PolicyDecision,
    SpendRecord,
)


def load_policy(path: str) -> Policy:
    """Read policy.yaml into a Policy. Addresses are normalised to lowercase."""
    with open(path) as f:
        raw = yaml.safe_load(f) or {}

    return Policy(
        per_transaction_max=Decimal(str(raw["per_transaction_max"])),
        daily_max=Decimal(str(raw["daily_max"])),
        hourly_max=Decimal(str(raw["hourly_max"])),
        rate_limit_per_minute=int(raw["rate_limit_per_minute"]),
        approval_threshold=Decimal(str(raw["approval_threshold"])),
        allowlist=[a.lower() for a in raw.get("allowlist", [])],
        denylist=[a.lower() for a in raw.get("denylist", [])],
    )


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
    ) -> PolicyDecision:
        p = self.policy
        recipient = request.recipient.lower()
        amount = request.amount

        # 1. Denylist — absolute, overrides everything else.
        if recipient in p.denylist:
            return PolicyDecision(
                Decision.DENY, f"recipient {request.recipient} is denylisted", "denylist"
            )

        # 2. Allowlist — if configured, recipient must be on it.
        if p.allowlist and recipient not in p.allowlist:
            return PolicyDecision(
                Decision.DENY,
                f"recipient {request.recipient} is not on the allowlist",
                "allowlist",
            )

        # 3. Sanity: no zero/negative payments.
        if amount <= 0:
            return PolicyDecision(
                Decision.DENY, f"amount {amount} must be positive", "amount_positive"
            )

        # 4. Per-transaction cap.
        if amount > p.per_transaction_max:
            return PolicyDecision(
                Decision.DENY,
                f"amount {amount} exceeds per-transaction max {p.per_transaction_max}",
                "per_transaction_max",
            )

        # 5. Rolling 1-hour spend cap.
        hour_spent = self._spent_since(history, now - timedelta(hours=1))
        if hour_spent + amount > p.hourly_max:
            return PolicyDecision(
                Decision.DENY,
                f"hourly spend {hour_spent}+{amount} would exceed {p.hourly_max}",
                "hourly_max",
            )

        # 6. Rolling 24-hour spend cap.
        day_spent = self._spent_since(history, now - timedelta(hours=24))
        if day_spent + amount > p.daily_max:
            return PolicyDecision(
                Decision.DENY,
                f"daily spend {day_spent}+{amount} would exceed {p.daily_max}",
                "daily_max",
            )

        # 7. Rate limit — count payments in the last 60 seconds.
        recent = self._count_since(history, now - timedelta(seconds=60))
        if recent >= p.rate_limit_per_minute:
            return PolicyDecision(
                Decision.DENY,
                f"rate limit: {recent} payments in the last minute "
                f"(max {p.rate_limit_per_minute})",
                "rate_limit_per_minute",
            )

        # 8. Above the approval threshold → allowed, but a human must confirm.
        if amount > p.approval_threshold:
            return PolicyDecision(
                Decision.NEEDS_APPROVAL,
                f"amount {amount} exceeds approval threshold {p.approval_threshold}; "
                "human confirmation required",
                "approval_threshold",
            )

        # 9. All checks passed.
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
