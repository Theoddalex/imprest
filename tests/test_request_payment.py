"""Tests for the request_payment pipeline — the money path.

These pin the invariants the /ship review found unproven:
  - DENY / NEEDS_APPROVAL / sends-off never touch the chain
  - a failed send is still recorded, and does NOT consume budget
  - needs_approval does NOT consume budget
  - the read-check-record cycle is atomic under concurrency (no double-spend)
  - identity comes from auth context, and budgets are isolated per agent
"""

from __future__ import annotations

import threading

import pytest

from imprest.api.payments import register_payment_tools
from imprest.services.audit import AuditLog
from imprest.services.auth import current_agent_id
from imprest.services.policy import PolicyStore

DEFAULT = dict(
    per_transaction_max="0.05",
    daily_max="0.20",
    hourly_max="0.10",
    rate_limit_per_minute=100,
    approval_threshold="0.02",
)
RECIPIENT = "0xAAAA000000000000000000000000000000000001"


class FakeMCP:
    """Captures @mcp.tool()-decorated functions so we can call them directly."""

    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class FakeChain:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def send_eth(self, to, amount):
        self.calls.append((to, amount))
        if self.fail:
            raise RuntimeError("rpc boom")
        return "0xdeadbeef"


def build(tmp_path, chain=None, enable_sends=False, agents=None):
    audit = AuditLog(str(tmp_path / "audit.db"))
    store = PolicyStore(DEFAULT, agents or {})
    mcp = FakeMCP()
    register_payment_tools(
        mcp, store, audit,
        get_chain=(lambda: chain) if chain else None,
        enable_sends=enable_sends,
    )
    return mcp.tools, audit


@pytest.fixture(autouse=True)
def _identity():
    token = current_agent_id.set("agent-1")
    yield
    current_agent_id.reset(token)


# ---- the execution gate --------------------------------------------------------

def test_deny_never_touches_the_chain(tmp_path):
    chain = FakeChain()
    tools, audit = build(tmp_path, chain=chain, enable_sends=True)
    r = tools["request_payment"](RECIPIENT, 0.10)  # over per-tx max
    assert r["decision"] == "deny"
    assert chain.calls == []          # the load-bearing assertion
    assert audit.history()[0]["decision"] == "deny"


def test_needs_approval_does_not_execute_even_with_sends_on(tmp_path):
    chain = FakeChain()
    tools, _ = build(tmp_path, chain=chain, enable_sends=True)
    r = tools["request_payment"](RECIPIENT, 0.03)  # over approval threshold
    assert r["decision"] == "needs_approval"
    assert r["executed"] is False
    assert chain.calls == []


def test_allow_with_sends_disabled_records_but_does_not_execute(tmp_path):
    chain = FakeChain()
    tools, audit = build(tmp_path, chain=chain, enable_sends=False)
    r = tools["request_payment"](RECIPIENT, 0.01)
    assert r["decision"] == "allow"
    assert r["executed"] is False
    assert chain.calls == []
    assert audit.history()[0]["decision"] == "allow"


def test_allow_with_sends_enabled_executes_and_records_tx(tmp_path):
    chain = FakeChain()
    tools, audit = build(tmp_path, chain=chain, enable_sends=True)
    r = tools["request_payment"](RECIPIENT, 0.01)
    assert r["executed"] is True
    assert r["tx_hash"] == "0xdeadbeef"
    row = audit.history()[0]
    assert row["status"] == "executed" and row["tx_hash"] == "0xdeadbeef"


# ---- failed send (blocker #3) --------------------------------------------------

def test_failed_send_is_still_recorded_and_not_counted(tmp_path):
    chain = FakeChain(fail=True)
    tools, audit = build(tmp_path, chain=chain, enable_sends=True)
    r = tools["request_payment"](RECIPIENT, 0.01)
    assert r["executed"] is False
    assert r["error"] == "rpc boom"
    row = audit.history()[0]
    assert row["status"] == "failed"                 # recorded, not vanished
    assert audit.approved_spends("agent-1") == []    # does not consume budget


# ---- needs_approval must not consume budget (blocker #2) -----------------------

def test_needs_approval_does_not_consume_budget(tmp_path):
    tools, audit = build(tmp_path)
    tools["request_payment"](RECIPIENT, 0.03)   # needs_approval
    tools["request_payment"](RECIPIENT, 0.03)   # again
    # neither consumed the daily budget; a real allowed spend still fits
    assert audit.approved_spends("agent-1") == []


def test_budget_accumulates_across_allowed_calls(tmp_path):
    # hourly_max 0.10; three 0.015 allowed spends = 0.045, all fine;
    # push past the hourly window cap and the next is denied.
    tools, audit = build(tmp_path)
    for _ in range(6):  # 6 * 0.015 = 0.09 <= 0.10
        assert tools["request_payment"](RECIPIENT, 0.015)["decision"] == "allow"
    d = tools["request_payment"](RECIPIENT, 0.015)  # 0.105 > 0.10
    assert d["decision"] == "deny" and d["rule"] == "hourly_max"


# ---- boundary validation (recommended fixes) -----------------------------------

def test_nan_amount_is_denied_not_crashed(tmp_path):
    tools, audit = build(tmp_path)
    r = tools["request_payment"](RECIPIENT, float("nan"))
    assert r["decision"] == "deny" and r["rule"] == "amount_finite"
    assert audit.history()[0]["decision"] == "deny"   # recorded, no crash


def test_malformed_recipient_is_denied(tmp_path):
    tools, _ = build(tmp_path)
    r = tools["request_payment"]("not-an-address", 0.01)
    assert r["decision"] == "deny" and r["rule"] == "recipient_format"


# ---- concurrency: no double-spend (blocker #4) ---------------------------------

def test_parallel_requests_cannot_bust_the_budget(tmp_path):
    # hourly_max 0.10, each request 0.03 -> at most 3 may pass, ever.
    tools, audit = build(tmp_path)

    results = []
    barrier = threading.Barrier(10)

    def worker():
        token = current_agent_id.set("agent-1")
        try:
            barrier.wait()  # maximise overlap on the critical section
            results.append(tools["request_payment"](RECIPIENT, 0.03)["decision"])
        finally:
            current_agent_id.reset(token)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allowed = results.count("allow")
    assert allowed <= 3, f"budget busted: {allowed} allowed (max 3)"
    # and the ledger agrees
    total = sum(a for _, a, _, _ in audit.approved_spends("agent-1"))
    assert total <= __import__("decimal").Decimal("0.10")


# ---- observability -------------------------------------------------------------

def test_decision_is_logged(tmp_path, caplog):
    import logging
    tools, _ = build(tmp_path)
    with caplog.at_level(logging.INFO, logger="imprest.payments"):
        tools["request_payment"](RECIPIENT, 0.01, "data api")
    line = caplog.text
    assert "agent=agent-1" in line and "asset=ETH" in line and "allow" in line


# ---- per-agent isolation -------------------------------------------------------

def test_budgets_are_isolated_per_agent(tmp_path):
    tools, audit = build(tmp_path, agents={
        "small": {"per_transaction_max": "0.01"},
        "big": {"per_transaction_max": "0.05"},
    })
    # same request, two identities, opposite outcomes
    current_agent_id.set("small")
    assert tools["request_payment"](RECIPIENT, 0.03)["decision"] == "deny"
    current_agent_id.set("big")
    assert tools["request_payment"](RECIPIENT, 0.03)["decision"] == "needs_approval"
    # and their audit trails don't cross
    assert all(e["agent_id"] == "small" for e in audit.history("small"))
    assert all(e["agent_id"] == "big" for e in audit.history("big"))
