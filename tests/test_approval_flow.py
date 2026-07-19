"""Tests for the approval-completion flow — the resume path for needs_approval.

Pins the invariants that make it safe:
  - only an admin identity can list or resolve pending approvals (an agent
    cannot clear its own)
  - approving executes and converts the row to a budget-consuming allow
  - rejecting never moves funds and never consumes budget
  - a human ok overrides ONLY the approval threshold — hard limits are re-checked
    against the current ledger at approval time
  - a pending row can be resolved once (no double-execute)
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from imprest.api.payments import register_payment_tools
from imprest.services.audit import AuditLog
from imprest.services.auth import current_agent_id, current_is_admin
from imprest.services.policy import PolicyStore

DEFAULT = dict(
    per_transaction_max="0.05", daily_max="0.20", hourly_max="0.10",
    rate_limit_per_minute=100, approval_threshold="0.02",
    assets={"USDC": {"per_transaction_max": "25", "hourly_max": "50",
                     "daily_max": "100", "approval_threshold": "5"}},
)
RECIPIENT = "0xAAAA000000000000000000000000000000000001"
BASE_SEPOLIA = 84532


class FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class FakeChain:
    def __init__(self, fail=False):
        self.calls = []          # ETH sends
        self.erc20_calls = []    # token transfers
        self.approve_calls = []  # token approvals
        self.fail = fail

    def send_eth(self, to, amount):
        self.calls.append((to, amount))
        if self.fail:
            raise RuntimeError("rpc boom")
        return "0xEXEC"

    def send_erc20(self, token_address, to, amount, decimals):
        self.erc20_calls.append((token_address, to, amount, decimals))
        if self.fail:
            raise RuntimeError("rpc boom")
        return "0xUSDCEXEC"

    def approve_erc20(self, token_address, spender, amount, decimals):
        self.approve_calls.append((token_address, spender, amount, decimals))
        if self.fail:
            raise RuntimeError("rpc boom")
        return "0xAPPROVEEXEC"


def build(tmp_path, chain=None, enable_sends=True, chain_id=BASE_SEPOLIA):
    audit = AuditLog(str(tmp_path / "audit.db"))
    store = PolicyStore(DEFAULT, {})
    mcp = FakeMCP()
    register_payment_tools(
        mcp, store, audit,
        get_chain=(lambda: chain) if chain else None,
        enable_sends=enable_sends, chain_id=chain_id,
    )
    return mcp.tools, audit


@pytest.fixture(autouse=True)
def _identity():
    a = current_agent_id.set("agent-1")
    b = current_is_admin.set(False)
    yield
    current_agent_id.reset(a)
    current_is_admin.reset(b)


def as_admin():
    current_is_admin.set(True)


def as_agent():
    current_is_admin.set(False)


# ---- admin gate ---------------------------------------------------------------

def test_agent_cannot_list_or_resolve(tmp_path):
    chain = FakeChain()
    tools, _ = build(tmp_path, chain=chain)
    as_agent()
    tools["request_payment"](RECIPIENT, 0.03)  # needs_approval
    assert "error" in tools["list_pending_approvals"]()
    r = tools["resolve_approval"](1)
    assert "error" in r and chain.calls == []


# ---- happy path: approve executes ---------------------------------------------

def test_needs_approval_shows_up_then_approve_executes(tmp_path):
    chain = FakeChain()
    tools, audit = build(tmp_path, chain=chain)
    as_admin()

    resp = tools["request_payment"](RECIPIENT, 0.03, "big one")
    assert resp["decision"] == "needs_approval" and resp["executed"] is False

    pending = tools["list_pending_approvals"]()["pending"]
    assert len(pending) == 1 and pending[0]["amount"] == "0.03"
    pid = pending[0]["id"]

    r = tools["resolve_approval"](pid, approve=True)
    assert r["resolved"] and r["executed"] and r["tx_hash"] == "0xEXEC"
    assert chain.calls == [(RECIPIENT, Decimal("0.03"))]

    # row is now an executed allow, attributed to the approver, and in the budget
    row = audit.history()[0]
    assert row["decision"] == "allow" and row["status"] == "executed"
    assert row["approver"] == "agent-1"
    assert sum(a for _, a, _, _ in audit.approved_spends("agent-1")) == Decimal("0.03")
    # and it's no longer pending
    assert tools["list_pending_approvals"]()["pending"] == []


# ---- unknown_recipient: "ask" — off-allowlist payments via the queue -----------

def test_ask_mode_unknown_recipient_freezes_then_approval_executes_once(tmp_path):
    stranger = "0xCCCC000000000000000000000000000000000003"
    chain = FakeChain()
    audit = AuditLog(str(tmp_path / "audit.db"))
    store = PolicyStore(
        {**DEFAULT, "allowlist": [RECIPIENT.lower()], "unknown_recipient": "ask"}, {}
    )
    mcp = FakeMCP()
    register_payment_tools(mcp, store, audit, get_chain=lambda: chain,
                           enable_sends=True, chain_id=BASE_SEPOLIA)
    tools = mcp.tools
    as_admin()

    # Off-allowlist recipient, within all limits -> queued, nothing moves.
    resp = tools["request_payment"](stranger, 0.01, "new vendor")
    assert resp["decision"] == "needs_approval"
    assert resp["rule"] == "allowlist_unknown_recipient"
    assert chain.calls == []

    # Human approves -> that ONE payment executes.
    pid = tools["list_pending_approvals"]()["pending"][0]["id"]
    r = tools["resolve_approval"](pid, approve=True, note="verified vendor")
    assert r["resolved"] and r["executed"]
    assert chain.calls == [(stranger, Decimal("0.01"))]

    # One-time semantics: the approval does NOT allowlist the address —
    # the very next payment to it freezes again.
    resp2 = tools["request_payment"](stranger, 0.01, "same vendor again")
    assert resp2["decision"] == "needs_approval"
    assert resp2["rule"] == "allowlist_unknown_recipient"
    assert chain.calls == [(stranger, Decimal("0.01"))]  # still just the one send


def test_ask_mode_never_queues_what_hard_limits_deny(tmp_path):
    stranger = "0xCCCC000000000000000000000000000000000003"
    chain = FakeChain()
    audit = AuditLog(str(tmp_path / "audit.db"))
    store = PolicyStore(
        {**DEFAULT, "allowlist": [RECIPIENT.lower()], "unknown_recipient": "ask"}, {}
    )
    mcp = FakeMCP()
    register_payment_tools(mcp, store, audit, get_chain=lambda: chain,
                           enable_sends=True, chain_id=BASE_SEPOLIA)
    tools = mcp.tools
    as_admin()

    resp = tools["request_payment"](stranger, 0.10)  # over per_transaction_max
    assert resp["decision"] == "deny" and resp["rule"] == "per_transaction_max"
    assert tools["list_pending_approvals"]()["pending"] == []


# ---- reject never moves funds -------------------------------------------------

def test_reject_does_not_execute_or_consume_budget(tmp_path):
    chain = FakeChain()
    tools, audit = build(tmp_path, chain=chain)
    as_admin()
    tools["request_payment"](RECIPIENT, 0.03)
    r = tools["resolve_approval"](1, approve=False, note="not now")
    assert r["resolved"] and r["executed"] is False and r["decision"] == "rejected"
    assert chain.calls == []
    assert audit.history()[0]["status"] == "rejected"
    assert audit.approved_spends("agent-1") == []


# ---- hard limits are re-checked at approval time ------------------------------

def test_approval_refused_if_a_hard_limit_now_blocks_it(tmp_path):
    chain = FakeChain()
    tools, audit = build(tmp_path, chain=chain)
    as_admin()

    tools["request_payment"](RECIPIENT, 0.03)   # id 1 -> needs_approval (pending)
    # meanwhile the agent spends up to near the hourly cap with allowed payments
    for _ in range(5):                           # 5 * 0.015 = 0.075 allowed
        assert tools["request_payment"](RECIPIENT, 0.015)["decision"] == "allow"

    # now approving the 0.03 would push hourly to 0.105 > 0.10 — refuse it
    r = tools["resolve_approval"](1, approve=True)
    assert r["resolved"] and r["executed"] is False
    assert r["decision"] == "deny" and r["rule"] == "hourly_max"
    assert chain.calls == [(RECIPIENT, Decimal("0.015"))] * 5  # the pending one never sent
    assert audit.history()[0]["status"] == "rejected"


# ---- resolve-once -------------------------------------------------------------

def test_cannot_resolve_the_same_approval_twice(tmp_path):
    chain = FakeChain()
    tools, _ = build(tmp_path, chain=chain)
    as_admin()
    tools["request_payment"](RECIPIENT, 0.03)
    assert tools["resolve_approval"](1, approve=True)["executed"] is True
    again = tools["resolve_approval"](1, approve=True)
    assert "error" in again
    assert len(chain.calls) == 1  # executed exactly once


# ---- failed send during approval ----------------------------------------------

def test_failed_send_during_approval_reverts_to_pending_and_is_retriable(tmp_path):
    # a transient RPC failure must NOT burn the operator's decision
    chain = FakeChain(fail=True)
    tools, audit = build(tmp_path, chain=chain)
    as_admin()
    tools["request_payment"](RECIPIENT, 0.03)
    r = tools["resolve_approval"](1, approve=True)
    assert r["resolved"] is False and r["executed"] is False and r["error"] == "rpc boom"
    # row is back to pending, not counted, and appears in the queue again
    row = audit.history()[0]
    assert row["decision"] == "needs_approval" and row["status"] == "recorded"
    assert audit.approved_spends("agent-1") == []
    assert [p["id"] for p in tools["list_pending_approvals"]()["pending"]] == [1]

    # now the RPC recovers and the operator retries — it executes
    chain.fail = False
    r2 = tools["resolve_approval"](1, approve=True)
    assert r2["resolved"] and r2["executed"] and r2["tx_hash"] == "0xEXEC"
    assert audit.history()[0]["status"] == "executed"


# ---- resolve routes the right on-chain call (tokens + approvals) --------------

def test_resolve_of_pending_usdc_transfer_routes_to_send_erc20(tmp_path):
    chain = FakeChain()
    tools, audit = build(tmp_path, chain=chain)
    as_admin()
    # 10 USDC > threshold 5, < per-tx 25 -> needs_approval
    r = tools["request_payment"](RECIPIENT, 10, "premium", "USDC")
    assert r["decision"] == "needs_approval"
    pid = tools["list_pending_approvals"]()["pending"][0]["id"]
    r = tools["resolve_approval"](pid, approve=True)
    assert r["resolved"] and r["executed"] and r["tx_hash"] == "0xUSDCEXEC"
    assert chain.calls == []  # not the ETH path
    _, to, amount, decimals = chain.erc20_calls[0]
    assert to == RECIPIENT and amount == Decimal("10") and decimals == 6
    assert audit.history()[0]["asset"] == "USDC"


def test_resolve_of_pending_approval_routes_to_approve_erc20(tmp_path):
    chain = FakeChain()
    tools, audit = build(tmp_path, chain=chain)
    as_admin()
    # 10 USDC allowance > threshold 5 -> needs_approval
    r = tools["request_approval"](RECIPIENT, 10, "USDC", "dex")
    assert r["decision"] == "needs_approval"
    pid = tools["list_pending_approvals"]()["pending"][0]["id"]
    r = tools["resolve_approval"](pid, approve=True)
    assert r["resolved"] and r["executed"] and r["tx_hash"] == "0xAPPROVEEXEC"
    assert r["operation"] == "approve" and r["asset"] == "USDC"
    assert chain.erc20_calls == [] and chain.calls == []
    assert len(chain.approve_calls) == 1


def test_unknown_payment_id_is_an_error(tmp_path):
    tools, _ = build(tmp_path, chain=FakeChain())
    as_admin()
    assert "error" in tools["resolve_approval"](999)
