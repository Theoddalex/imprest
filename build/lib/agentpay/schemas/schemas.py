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
    recipient: str          # 0x… address
    amount: Decimal         # in ETH
    reason: str = ""        # free-text: what the payment is for (for the audit log)


@dataclass(frozen=True)
class SpendRecord:
    """A payment that was previously approved — the history the engine reasons over."""

    recipient: str
    amount: Decimal
    timestamp: datetime


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


@dataclass
class Policy:
    """The spend policy — this is the product's config, not code.

    Loaded from policy.yaml. Every field is a guardrail the agent cannot override.
    """

    per_transaction_max: Decimal          # reject any single payment above this
    daily_max: Decimal                    # reject if rolling-24h total would exceed this
    hourly_max: Decimal                   # reject if rolling-1h total would exceed this
    rate_limit_per_minute: int            # max number of payments in any 60s window
    approval_threshold: Decimal           # payments above this need human approval
    allowlist: list[str] = field(default_factory=list)  # if non-empty, ONLY these recipients
    denylist: list[str] = field(default_factory=list)   # never pay these, overrides everything
