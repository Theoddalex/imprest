"""Tests for the allowance ledger — the standing-liability cap on approve().

Budgets reset with their rolling window; an ERC-20 allowance does NOT — it
stays live until spent or revoked. Without a ledger an agent could stack live
allowances across days far beyond any single window's budget (the documented
mainnet gate). These tests pin the closing of that gap:

  - the engine caps the TOTAL of live allowances per asset
  - approve() overwrites: re-approving a spender REPLACES their entry
  - approve(spender, 0) is a revoke — always allowed, frees the cap
  - the audit log reconstructs the ledger (latest counting approve per
    (asset, spender), never time-bounded, failed broadcasts skipped)
  - the tool pipeline enforces the cap end-to-end, including the re-check
    when a human resolves a pending approval
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from agentpay.api.payments import register_payment_tools
from agentpay.schemas.schemas import (
    AllowanceRecord,
    AssetLimits,
    Decision,
    PaymentRequest,
    Policy,
    PolicyDecision,
)
from agentpay.services.audit import AuditLog
from agentpay.services.auth import current_agent_id, current_is_admin
from agentpay.services.policy import PolicyEngine, PolicyStore, _policy_from_dict

NOW = datetime(2026, 7, 17, 12, 0, 0)
SPENDER_X = "0xCCCC000000000000000000000000000000000003"
SPENDER_Y = "0xDDDD000000000000000000000000000000000004"
BASE_SEPOLIA = 84532


def make_policy(outstanding_cap="30", **usdc_overrides) -> Policy:
    usdc = dict(
        per_transaction_max=Decimal("25"),
        daily_max=Decimal("100"),
        hourly_max=Decimal("50"),
        approval_threshold=Decimal("20"),
        max_outstanding_allowance=(
            Decimal(outstanding_cap) if outstanding_cap is not None else None
        ),
    )
    usdc.update(usdc_overrides)
    return Policy(
        per_transaction_max=Decimal("0.05"),
        daily_max=Decimal("0.20"),
        hourly_max=Decimal("0.10"),
        rate_limit_per_minute=100,
        approval_threshold=Decimal("0.02"),
        assets={"USDC": AssetLimits(**usdc)},
    )


def approve_req(amount: str, spender: str = SPENDER_Y) -> PaymentRequest:
    return PaymentRequest(
        agent_id="agent-1", recipient=spender, amount=Decimal(amount),
        asset="USDC", operation="approve",
    )


def live(spender: str, amount: str, asset: str = "USDC") -> AllowanceRecord:
    return AllowanceRecord(spender=spender, amount=Decimal(amount), asset=asset)


# ---- engine: the outstanding-allowance cap -------------------------------------

def test_accumulation_across_windows_is_blocked():
    # THE mainnet-gate scenario: an old grant is long outside every budget
    # window (history is empty), but the allowance is still live — a new grant
    # that would push the live total past the cap must be denied.
    engine = PolicyEngine(make_policy(outstanding_cap="30"))
    d = engine.evaluate(
        approve_req("15", SPENDER_Y), history=[], now=NOW,
        allowances=[live(SPENDER_X, "20")],  # granted days ago, still live
    )
    assert d.decision is Decision.DENY
    assert d.rule == "max_outstanding_allowance"


def test_reapproving_a_spender_replaces_not_adds():
    # approve() overwrites on-chain, so the ledger must model replacement:
    # X already holds 20; re-approving X for 15 makes the total 15, not 35.
    engine = PolicyEngine(make_policy(outstanding_cap="30"))
    d = engine.evaluate(
        approve_req("15", SPENDER_X), history=[], now=NOW,
        allowances=[live(SPENDER_X, "20")],
    )
    assert d.decision is Decision.ALLOW


def test_revoke_is_always_allowed_and_transfers_of_zero_are_not():
    engine = PolicyEngine(make_policy(outstanding_cap="30"))
    revoke = engine.evaluate(
        approve_req("0", SPENDER_X), history=[], now=NOW,
        allowances=[live(SPENDER_X, "30")],  # cap fully consumed
    )
    assert revoke.decision is Decision.ALLOW
    zero_transfer = engine.evaluate(
        PaymentRequest(agent_id="agent-1", recipient=SPENDER_X,
                       amount=Decimal("0"), asset="USDC"),
        history=[], now=NOW,
    )
    assert zero_transfer.rule == "amount_positive"  # 0 stays invalid for transfers


def test_cap_defaults_to_daily_max_when_unset():
    # safe-by-default: an operator who never heard of the knob still gets a cap.
    engine = PolicyEngine(make_policy(outstanding_cap=None))  # daily_max=100
    over = engine.evaluate(
        approve_req("15", SPENDER_Y), history=[], now=NOW,
        allowances=[live(SPENDER_X, "90")],  # 90+15 > 100
    )
    assert over.rule == "max_outstanding_allowance"
    under = engine.evaluate(
        approve_req("10", SPENDER_Y), history=[], now=NOW,
        allowances=[live(SPENDER_X, "90")],  # 90+10 == 100, at the cap
    )
    assert under.decision is Decision.ALLOW


def test_ledger_is_per_asset():
    # a pile of live USDC allowances must not block approving a different token
    p = make_policy(outstanding_cap="30")
    p.assets["DAI"] = AssetLimits(
        per_transaction_max=Decimal("25"), daily_max=Decimal("100"),
        hourly_max=Decimal("50"), approval_threshold=Decimal("20"),
        max_outstanding_allowance=Decimal("30"),
    )
    engine = PolicyEngine(p)
    d = engine.evaluate(
        PaymentRequest(agent_id="agent-1", recipient=SPENDER_Y,
                       amount=Decimal("15"), asset="DAI", operation="approve"),
        history=[], now=NOW,
        allowances=[live(SPENDER_X, "30", asset="USDC")],
    )
    assert d.decision is Decision.ALLOW


def test_transfers_ignore_the_allowance_ledger():
    # the cap is a liability cap on grants; direct transfers answer to budgets
    engine = PolicyEngine(make_policy(outstanding_cap="30"))
    d = engine.evaluate(
        PaymentRequest(agent_id="agent-1", recipient=SPENDER_Y,
                       amount=Decimal("10"), asset="USDC"),
        history=[], now=NOW,
        allowances=[live(SPENDER_X, "30")],
    )
    assert d.decision is Decision.ALLOW


def test_yaml_config_parses_the_new_knob():
    p = _policy_from_dict({
        "per_transaction_max": "0.05", "daily_max": "0.20", "hourly_max": "0.10",
        "rate_limit_per_minute": 5, "approval_threshold": "0.02",
        "assets": {"USDC": {"per_transaction_max": "25", "daily_max": "100",
                            "hourly_max": "50", "approval_threshold": "20",
                            "max_outstanding_allowance": "50"}},
    })
    assert p.limits_for("USDC").outstanding_allowance_cap == Decimal("50")


# ---- audit: reconstructing the ledger from the log ------------------------------

def _record_approve(audit, amount, spender=SPENDER_X, decision=Decision.ALLOW,
                    agent="agent-1", asset="USDC", days_ago=0):
    req = PaymentRequest(agent_id=agent, recipient=spender,
                         amount=Decimal(amount), asset=asset, operation="approve")
    verdict = PolicyDecision(decision, "test", "ok")
    ts = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return audit.record(req, verdict, ts)


def _ledger(audit, agent="agent-1"):
    return {(asset, s): a for s, a, asset in audit.outstanding_allowances(agent)}


def test_latest_approve_per_spender_wins(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    _record_approve(audit, "20", SPENDER_X, days_ago=3)  # overwritten below
    _record_approve(audit, "5", SPENDER_X)
    _record_approve(audit, "10", SPENDER_Y)
    assert _ledger(audit) == {("USDC", SPENDER_X.lower()): Decimal("5"),
                              ("USDC", SPENDER_Y.lower()): Decimal("10")}


def test_ledger_is_not_time_bounded(tmp_path):
    # an allowance granted last month is exactly as live as one granted now
    audit = AuditLog(str(tmp_path / "a.db"))
    _record_approve(audit, "20", SPENDER_X, days_ago=30)
    assert _ledger(audit) == {("USDC", SPENDER_X.lower()): Decimal("20")}


def test_failed_broadcast_keeps_the_previous_grant_live(tmp_path):
    # a failed approve tx never reached the chain: the OLD allowance stands
    audit = AuditLog(str(tmp_path / "a.db"))
    _record_approve(audit, "20", SPENDER_X)
    row = _record_approve(audit, "5", SPENDER_X)
    audit.mark_failed(row, "rpc boom")
    assert _ledger(audit) == {("USDC", SPENDER_X.lower()): Decimal("20")}


def test_pending_and_denied_approvals_are_not_live(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    _record_approve(audit, "20", SPENDER_X, decision=Decision.NEEDS_APPROVAL)
    _record_approve(audit, "20", SPENDER_Y, decision=Decision.DENY)
    assert _ledger(audit) == {}


def test_revoke_drops_the_spender_from_the_ledger(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    _record_approve(audit, "20", SPENDER_X)
    _record_approve(audit, "0", SPENDER_X)  # revoke
    assert _ledger(audit) == {}


def test_ledger_is_per_agent(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    _record_approve(audit, "20", SPENDER_X, agent="agent-1")
    _record_approve(audit, "9", SPENDER_X, agent="agent-2")
    assert _ledger(audit, "agent-1") == {("USDC", SPENDER_X.lower()): Decimal("20")}
    assert _ledger(audit, "agent-2") == {("USDC", SPENDER_X.lower()): Decimal("9")}


# ---- tool pipeline: end-to-end enforcement --------------------------------------

DEFAULT = dict(
    per_transaction_max="0.05", daily_max="0.20", hourly_max="0.10",
    rate_limit_per_minute=100, approval_threshold="0.02",
    assets={"USDC": {"per_transaction_max": "25", "hourly_max": "50",
                     "daily_max": "100", "approval_threshold": "20",
                     "max_outstanding_allowance": "30"}},
)


class FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class FakeChain:
    def __init__(self):
        self.approve_calls = []

    def approve_erc20(self, token_address, spender, amount, decimals):
        self.approve_calls.append((spender, amount))
        return "0xAPPROVE"


def build(tmp_path):
    audit = AuditLog(str(tmp_path / "audit.db"))
    store = PolicyStore(DEFAULT, {})
    chain = FakeChain()
    mcp = FakeMCP()
    register_payment_tools(
        mcp, store, audit, get_chain=lambda: chain,
        enable_sends=True, chain_id=BASE_SEPOLIA,
    )
    return mcp.tools, audit, chain


@pytest.fixture(autouse=True)
def _identity():
    token = current_agent_id.set("agent-1")
    yield
    current_agent_id.reset(token)


def test_stacking_allowances_hits_the_cap_through_the_tool(tmp_path):
    tools, audit, chain = build(tmp_path)
    assert tools["request_approval"](SPENDER_X, 18, "USDC")["decision"] == "allow"
    r = tools["request_approval"](SPENDER_Y, 15, "USDC")  # 18+15 > 30
    assert r["decision"] == "deny" and r["rule"] == "max_outstanding_allowance"
    assert len(chain.approve_calls) == 1  # the second grant never reached chain
    assert audit.history()[-1]["rule"] == "max_outstanding_allowance"


def test_revoke_through_the_tool_frees_the_cap(tmp_path):
    tools, _, chain = build(tmp_path)
    tools["request_approval"](SPENDER_X, 18, "USDC")
    assert tools["request_approval"](SPENDER_Y, 15, "USDC")["decision"] == "deny"
    revoke = tools["request_approval"](SPENDER_X, 0, "USDC", "rotate spender")
    assert revoke["decision"] == "allow" and revoke["executed"] is True
    assert chain.approve_calls[-1] == (SPENDER_X, Decimal("0"))  # real on-chain revoke
    retry = tools["request_approval"](SPENDER_Y, 15, "USDC")
    assert retry["decision"] == "allow" and retry["executed"] is True


def test_reapproving_same_spender_through_the_tool_replaces(tmp_path):
    tools, _, chain = build(tmp_path)
    tools["request_approval"](SPENDER_X, 18, "USDC")
    r = tools["request_approval"](SPENDER_X, 20, "USDC")  # replace, not 18+20
    assert r["decision"] == "allow" and r["executed"] is True


def test_resolving_a_pending_approval_rechecks_the_ledger(tmp_path):
    # a human ok must not bust the outstanding cap: grants made while the
    # request sat in the queue count against it at approval time.
    tools, audit, chain = build(tmp_path)
    queued = tools["request_approval"](SPENDER_X, 22, "USDC")  # over 20 threshold
    assert queued["decision"] == "needs_approval"
    tools["request_approval"](SPENDER_Y, 15, "USDC")  # granted meanwhile

    admin_tok = current_is_admin.set(True)
    id_tok = current_agent_id.set("ops")
    try:
        pending = audit.pending_approvals()[0]
        r = tools["resolve_approval"](pending["id"], approve=True)
    finally:
        current_agent_id.reset(id_tok)
        current_is_admin.reset(admin_tok)

    assert r["decision"] == "deny" and r["executed"] is False
    assert "outstanding cap" in r["detail"]
    assert [s for s, _ in chain.approve_calls] == [SPENDER_Y]  # only the live grant
