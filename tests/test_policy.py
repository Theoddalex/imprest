"""Exhaustive tests for the policy engine.

The engine guards money, so every rule gets a test: the happy path, the exact
boundary, and the failure. Time is injected (`NOW`) so tests are deterministic
— no real clock, no flakiness.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

import pytest

from agentmandate.schemas.schemas import (
    Decision,
    PaymentRequest,
    Policy,
    SpendRecord,
)
from agentmandate.services.policy import PolicyEngine

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


# ---- unknown_recipient: "ask" ---------------------------------------------------

def ask_policy(**overrides) -> Policy:
    return make_policy(
        allowlist=[ALICE.lower()], unknown_recipient="ask", **overrides
    )


def test_ask_mode_escalates_unknown_recipient_instead_of_denying():
    engine = PolicyEngine(ask_policy())
    d = engine.evaluate(req("0.001", recipient=BOB), history=[], now=NOW)
    assert d.decision is Decision.NEEDS_APPROVAL
    assert d.rule == "allowlist_unknown_recipient"


def test_ask_mode_still_denies_when_a_hard_limit_is_breached():
    # The escalation is NOT a bypass: a request over the per-tx cap dies on
    # the cap, it never reaches the approval queue.
    engine = PolicyEngine(ask_policy())
    d = engine.evaluate(req("0.10", recipient=BOB), history=[], now=NOW)
    assert d.decision is Decision.DENY
    assert d.rule == "per_transaction_max"


def test_ask_mode_still_denies_budget_breaches():
    engine = PolicyEngine(ask_policy())
    history = [spend("0.09", minutes_ago=10)]
    d = engine.evaluate(req("0.02", recipient=BOB), history=history, now=NOW)
    assert d.decision is Decision.DENY
    assert d.rule == "hourly_max"


def test_ask_mode_denylist_stays_absolute():
    engine = PolicyEngine(ask_policy(denylist=[BOB.lower()]))
    d = engine.evaluate(req("0.001", recipient=BOB), history=[], now=NOW)
    assert d.decision is Decision.DENY
    assert d.rule == "denylist"


def test_ask_mode_leaves_allowlisted_recipients_untouched():
    engine = PolicyEngine(ask_policy())
    d = engine.evaluate(req("0.001", recipient=ALICE), history=[], now=NOW)
    assert d.decision is Decision.ALLOW


def test_ask_mode_is_irrelevant_with_an_empty_allowlist():
    engine = PolicyEngine(make_policy(allowlist=[], unknown_recipient="ask"))
    d = engine.evaluate(req("0.001", recipient=BOB), history=[], now=NOW)
    assert d.decision is Decision.ALLOW


def test_unknown_recipient_config_typo_fails_closed_at_load():
    from agentmandate.services.policy import _policy_from_dict

    with pytest.raises(ValueError, match="unknown_recipient"):
        _policy_from_dict(dict(
            per_transaction_max="0.05", daily_max="0.20", hourly_max="0.10",
            rate_limit_per_minute=5, approval_threshold="0.02",
            unknown_recipient="allow",   # not a valid mode
        ))


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
