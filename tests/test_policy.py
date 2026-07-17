"""Exhaustive tests for the policy engine.

The engine guards money, so every rule gets a test: the happy path, the exact
boundary, and the failure. Time is injected (`NOW`) so tests are deterministic
— no real clock, no flakiness.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

import pytest

from agentpay.schemas.schemas import (
    Decision,
    PaymentRequest,
    Policy,
    SpendRecord,
)
from agentpay.services.policy import PolicyEngine

NOW = datetime(2026, 7, 17, 12, 0, 0)
ALICE = "0xAAAA000000000000000000000000000000000001"
BOB = "0xBBBB000000000000000000000000000000000002"


def make_policy(**overrides) -> Policy:
    base = dict(
        per_transaction_max=Decimal("0.05"),
        daily_max=Decimal("0.20"),
        hourly_max=Decimal("0.10"),
        rate_limit_per_minute=5,
        approval_threshold=Decimal("0.02"),
        allowlist=[],
        denylist=[],
    )
    base.update(overrides)
    return Policy(**base)


def req(amount: str, recipient: str = ALICE) -> PaymentRequest:
    return PaymentRequest(agent_id="agent-1", recipient=recipient, amount=Decimal(amount))


def spend(amount: str, minutes_ago: int = 0, recipient: str = ALICE) -> SpendRecord:
    return SpendRecord(
        recipient=recipient,
        amount=Decimal(amount),
        timestamp=NOW - timedelta(minutes=minutes_ago),
    )


# ---- happy path ---------------------------------------------------------------

def test_small_payment_within_policy_is_allowed():
    engine = PolicyEngine(make_policy())
    d = engine.evaluate(req("0.01"), history=[], now=NOW)
    assert d.decision is Decision.ALLOW
    assert d.allowed


# ---- denylist / allowlist -----------------------------------------------------

def test_denylist_blocks_even_a_valid_payment():
    engine = PolicyEngine(make_policy(denylist=[BOB.lower()]))
    d = engine.evaluate(req("0.001", recipient=BOB), history=[], now=NOW)
    assert d.decision is Decision.DENY
    assert d.rule == "denylist"


def test_denylist_is_case_insensitive():
    engine = PolicyEngine(make_policy(denylist=[BOB.lower()]))
    # request uses the checksummed (mixed-case) form
    d = engine.evaluate(req("0.001", recipient=BOB.upper()), history=[], now=NOW)
    assert d.decision is Decision.DENY


def test_allowlist_blocks_recipient_not_on_it():
    engine = PolicyEngine(make_policy(allowlist=[ALICE.lower()]))
    d = engine.evaluate(req("0.001", recipient=BOB), history=[], now=NOW)
    assert d.decision is Decision.DENY
    assert d.rule == "allowlist"


def test_allowlist_permits_recipient_on_it():
    engine = PolicyEngine(make_policy(allowlist=[ALICE.lower()]))
    d = engine.evaluate(req("0.001", recipient=ALICE), history=[], now=NOW)
    assert d.decision is Decision.ALLOW


def test_empty_allowlist_means_no_allowlist_restriction():
    engine = PolicyEngine(make_policy(allowlist=[]))
    d = engine.evaluate(req("0.001", recipient=BOB), history=[], now=NOW)
    assert d.decision is Decision.ALLOW


# ---- amount sanity ------------------------------------------------------------

@pytest.mark.parametrize("amount", ["0", "-0.01"])
def test_zero_or_negative_is_denied(amount):
    engine = PolicyEngine(make_policy())
    d = engine.evaluate(req(amount), history=[], now=NOW)
    assert d.decision is Decision.DENY
    assert d.rule == "amount_positive"


# ---- per-transaction cap ------------------------------------------------------

def test_at_per_transaction_max_is_allowed_but_over_is_denied():
    engine = PolicyEngine(make_policy(per_transaction_max=Decimal("0.05"),
                                      approval_threshold=Decimal("0.05")))
    assert engine.evaluate(req("0.05"), [], NOW).decision is Decision.ALLOW   # exactly at cap
    over = engine.evaluate(req("0.0500001"), [], NOW)
    assert over.decision is Decision.DENY
    assert over.rule == "per_transaction_max"


# ---- rolling windows ----------------------------------------------------------

def test_hourly_cap_counts_only_last_hour():
    engine = PolicyEngine(make_policy(hourly_max=Decimal("0.10"),
                                      approval_threshold=Decimal("1")))
    # 0.09 spent 30 min ago; +0.02 now would be 0.11 > 0.10 → deny
    history = [spend("0.09", minutes_ago=30)]
    assert engine.evaluate(req("0.02"), history, NOW).rule == "hourly_max"
    # same spend but 90 min ago falls outside the window → allowed
    old = [spend("0.09", minutes_ago=90)]
    assert engine.evaluate(req("0.02"), old, NOW).decision is Decision.ALLOW


def test_daily_cap_counts_last_24h():
    engine = PolicyEngine(make_policy(daily_max=Decimal("0.20"),
                                      hourly_max=Decimal("1"),
                                      per_transaction_max=Decimal("1"),
                                      approval_threshold=Decimal("1")))
    history = [spend("0.19", minutes_ago=600)]  # 10h ago, inside 24h
    assert engine.evaluate(req("0.02"), history, NOW).rule == "daily_max"


# ---- rate limit ---------------------------------------------------------------

def test_rate_limit_blocks_the_sixth_payment_in_a_minute():
    engine = PolicyEngine(make_policy(rate_limit_per_minute=5,
                                      hourly_max=Decimal("1"),
                                      daily_max=Decimal("1"),
                                      approval_threshold=Decimal("1")))
    history = [spend("0.001", minutes_ago=0) for _ in range(5)]
    d = engine.evaluate(req("0.001"), history, NOW)
    assert d.decision is Decision.DENY
    assert d.rule == "rate_limit_per_minute"


def test_rate_limit_ignores_payments_older_than_a_minute():
    engine = PolicyEngine(make_policy(rate_limit_per_minute=5,
                                      hourly_max=Decimal("1"),
                                      daily_max=Decimal("1"),
                                      approval_threshold=Decimal("1")))
    history = [spend("0.001", minutes_ago=2) for _ in range(5)]  # all >60s ago
    assert engine.evaluate(req("0.001"), history, NOW).decision is Decision.ALLOW


# ---- approval threshold -------------------------------------------------------

def test_above_approval_threshold_needs_approval_not_denied():
    engine = PolicyEngine(make_policy(approval_threshold=Decimal("0.02")))
    d = engine.evaluate(req("0.03"), history=[], now=NOW)
    assert d.decision is Decision.NEEDS_APPROVAL
    assert d.allowed  # still allowed to proceed — just gated on a human
    assert d.rule == "approval_threshold"


# ---- rule priority ------------------------------------------------------------

def test_denylist_beats_everything_including_bad_amount():
    # a denylisted recipient AND a zero amount → denylist should win (checked first)
    engine = PolicyEngine(make_policy(denylist=[ALICE.lower()]))
    d = engine.evaluate(req("0"), history=[], now=NOW)
    assert d.rule == "denylist"
