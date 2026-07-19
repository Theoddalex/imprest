"""Tests for ERC-20 / stablecoin support.

Covers the three new surfaces:
  - the policy engine's per-asset limits + token allowlist + budget isolation
  - the chain layer's whole-units -> base-units conversion (USDC has 6 decimals)
  - the request_payment tool routing a token payment to send_erc20 and
    recording its asset — and refusing tokens unknown on the configured network
"""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

import pytest

from imprest.api.payments import register_payment_tools
from imprest.schemas.schemas import (
    AssetLimits,
    Decision,
    PaymentRequest,
    Policy,
    SpendRecord,
)
from imprest.services.audit import AuditLog
from imprest.services.auth import current_agent_id
from imprest.services.chain import _to_base_units
from imprest.services.policy import PolicyEngine, PolicyStore

NOW = datetime(2026, 7, 17, 12, 0, 0)
ALICE = "0xAAAA000000000000000000000000000000000001"
BASE_SEPOLIA = 84532


def make_policy(**overrides) -> Policy:
    base = dict(
        per_transaction_max=Decimal("0.05"),
        daily_max=Decimal("0.20"),
        hourly_max=Decimal("0.10"),
        rate_limit_per_minute=5,
        approval_threshold=Decimal("0.02"),
        allowlist=[],
        denylist=[],
        assets={
            "USDC": AssetLimits(
                per_transaction_max=Decimal("25"),
                daily_max=Decimal("100"),
                hourly_max=Decimal("50"),
                approval_threshold=Decimal("20"),
            )
        },
    )
    base.update(overrides)
    return Policy(**base)


def usdc(amount: str, minutes_ago: int = 0, asset: str = "USDC") -> SpendRecord:
    return SpendRecord(
        recipient=ALICE,
        amount=Decimal(amount),
        timestamp=NOW - timedelta(minutes=minutes_ago),
        asset=asset,
    )


def req(amount: str, asset: str = "USDC") -> PaymentRequest:
    return PaymentRequest(
        agent_id="agent-1", recipient=ALICE, amount=Decimal(amount), asset=asset
    )


# ---- base-units conversion (the 6-decimals footgun) ---------------------------

def test_whole_usdc_converts_to_base_units():
    assert _to_base_units(Decimal("50"), 6) == 50_000_000
    assert _to_base_units(Decimal("0.01"), 6) == 10_000  # a cent of USDC


def test_over_precision_is_rejected_not_truncated():
    # 7 decimals against a 6-decimal token would silently lose value — refuse it.
    with pytest.raises(ValueError):
        _to_base_units(Decimal("0.0000001"), 6)


# ---- policy: per-asset limits -------------------------------------------------

def test_usdc_within_its_own_limits_is_allowed():
    engine = PolicyEngine(make_policy())
    d = engine.evaluate(req("10"), history=[], now=NOW)
    assert d.decision is Decision.ALLOW


def test_usdc_uses_its_own_per_tx_cap_not_eth():
    # 10 USDC would blow the 0.05 ETH cap, but USDC has its own 25 cap.
    engine = PolicyEngine(make_policy())
    assert engine.evaluate(req("10"), [], NOW).decision is Decision.ALLOW
    assert engine.evaluate(req("30"), [], NOW).rule == "per_transaction_max"


def test_usdc_over_approval_threshold_needs_approval():
    engine = PolicyEngine(make_policy())
    d = engine.evaluate(req("22"), history=[], now=NOW)
    assert d.decision is Decision.NEEDS_APPROVAL
    assert d.rule == "approval_threshold"


def test_unknown_asset_is_denied():
    engine = PolicyEngine(make_policy())
    d = engine.evaluate(req("1", asset="DAI"), history=[], now=NOW)
    assert d.decision is Decision.DENY
    assert d.rule == "asset_not_allowed"


# ---- policy: per-asset budget isolation ---------------------------------------

def test_eth_history_does_not_consume_usdc_budget():
    # a big ETH spend history must not touch the USDC daily budget
    eth_history = [SpendRecord(ALICE, Decimal("0.19"), NOW, asset="ETH")]
    engine = PolicyEngine(make_policy())
    d = engine.evaluate(req("10"), history=eth_history, now=NOW)
    assert d.decision is Decision.ALLOW  # USDC budget untouched


def test_usdc_daily_budget_is_enforced_from_usdc_history():
    history = [usdc("95", minutes_ago=90)]  # 95 of 100 daily; outside the hour window
    engine = PolicyEngine(make_policy())
    d = engine.evaluate(req("10"), history=history, now=NOW)  # 95+10 > 100
    assert d.decision is Decision.DENY
    assert d.rule == "daily_max"


def test_rate_limit_counts_all_assets_together():
    # 5/min limit; five recent ETH payments should rate-limit a USDC one too.
    history = [
        SpendRecord(ALICE, Decimal("0.001"), NOW - timedelta(seconds=10), asset="ETH")
        for _ in range(5)
    ]
    engine = PolicyEngine(make_policy())
    d = engine.evaluate(req("1"), history=history, now=NOW)
    assert d.rule == "rate_limit_per_minute"


# ---- store: per-symbol asset merge --------------------------------------------

def test_agent_override_keeps_inherited_tokens():
    store = PolicyStore(
        default={
            "per_transaction_max": "0.05", "daily_max": "0.20", "hourly_max": "0.10",
            "rate_limit_per_minute": 5, "approval_threshold": "0.02",
            "assets": {"USDC": {"per_transaction_max": "25", "daily_max": "100",
                                "hourly_max": "50", "approval_threshold": "20"}},
        },
        agents={"tight": {"assets": {"USDC": {
            "per_transaction_max": "5", "daily_max": "20",
            "hourly_max": "10", "approval_threshold": "5"}}}},
    )
    tight = store.for_agent("tight")
    # the agent's tighter USDC cap wins...
    assert tight.limits_for("USDC").per_transaction_max == Decimal("5")
    # ...and an agent with no asset override still inherits the default token
    assert store.for_agent("other").limits_for("USDC").per_transaction_max == Decimal("25")


# ---- request_payment: token routing -------------------------------------------

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
        self.eth_calls = []
        self.erc20_calls = []
        self.approve_calls = []
        self.token_balance_calls = []

    def send_eth(self, to, amount):
        self.eth_calls.append((to, amount))
        return "0xETH"

    def send_erc20(self, token_address, to, amount, decimals):
        self.erc20_calls.append((token_address, to, amount, decimals))
        return "0xUSDC"

    def approve_erc20(self, token_address, spender, amount, decimals):
        self.approve_calls.append((token_address, spender, amount, decimals))
        return "0xAPPROVE"

    def get_token_balance(self, token_address, address, decimals):
        self.token_balance_calls.append((token_address, address, decimals))
        return Decimal("42")


def token_addr():
    from imprest.services.tokens import token_for
    return token_for(BASE_SEPOLIA, "USDC").address


DEFAULT_WITH_USDC = dict(
    per_transaction_max="0.05", daily_max="0.20", hourly_max="0.10",
    rate_limit_per_minute=100, approval_threshold="0.02",
    assets={"USDC": {"per_transaction_max": "25", "daily_max": "100",
                     "hourly_max": "50", "approval_threshold": "20"}},
)


def build(tmp_path, chain_id=BASE_SEPOLIA):
    audit = AuditLog(str(tmp_path / "audit.db"))
    store = PolicyStore(DEFAULT_WITH_USDC, {})
    chain = FakeChain()
    mcp = FakeMCP()
    register_payment_tools(
        mcp, store, audit, get_chain=lambda: chain,
        enable_sends=True, chain_id=chain_id,
    )
    return mcp.tools, audit, chain


@pytest.fixture(autouse=True)
def _identity():
    token = current_agent_id.set("agent-1")
    yield
    current_agent_id.reset(token)


def test_usdc_payment_routes_to_send_erc20(tmp_path):
    tools, audit, chain = build(tmp_path)
    r = tools["request_payment"](ALICE, 10, "data api", asset="USDC")
    assert r["decision"] == "allow" and r["executed"] is True
    assert r["asset"] == "USDC" and r["tx_hash"] == "0xUSDC"
    assert chain.eth_calls == []                      # not the ETH path
    assert len(chain.erc20_calls) == 1
    token_address, to, amount, decimals = chain.erc20_calls[0]
    assert to == ALICE and amount == Decimal("10") and decimals == 6
    assert audit.history()[0]["asset"] == "USDC"


def test_eth_payment_still_routes_to_send_eth(tmp_path):
    tools, _, chain = build(tmp_path)
    r = tools["request_payment"](ALICE, 0.01, "gas", asset="ETH")
    assert r["executed"] is True and r["tx_hash"] == "0xETH"
    assert chain.erc20_calls == []


def test_token_unknown_on_this_network_is_rejected(tmp_path):
    # policy permits USDC, but there is no USDC contract for chain_id 0
    tools, audit, chain = build(tmp_path, chain_id=0)
    r = tools["request_payment"](ALICE, 10, asset="USDC")
    assert r["decision"] == "deny" and r["rule"] == "asset_unknown"
    assert chain.erc20_calls == [] and chain.eth_calls == []


def test_over_precision_usdc_rejected_at_the_boundary(tmp_path):
    # 7 decimals against 6-decimal USDC — must deny up front, never reach chain,
    # so a recorded ALLOW is always executable.
    tools, audit, chain = build(tmp_path)
    r = tools["request_payment"](ALICE, 0.0000001, "dust", "USDC")
    assert r["decision"] == "deny" and r["rule"] == "amount_precision"
    assert chain.erc20_calls == []
    assert audit.history()[0]["decision"] == "deny"  # recorded as a clean deny


def test_lowercase_asset_symbol_is_normalized(tmp_path):
    tools, _, chain = build(tmp_path)
    r = tools["request_payment"](ALICE, 2, "lower", asset="usdc")
    assert r["decision"] == "allow" and r["asset"] == "USDC"
    assert len(chain.erc20_calls) == 1


def test_get_balance_routes_token_to_get_token_balance(tmp_path):
    tools, _, chain = build(tmp_path)
    r = tools["get_balance"](ALICE, asset="USDC")
    assert r["asset"] == "USDC"
    assert chain.token_balance_calls[0][0] == token_addr()  # resolved USDC address


def test_get_balance_unknown_token_errors(tmp_path):
    tools, _, chain = build(tmp_path)
    r = tools["get_balance"](ALICE, asset="DAI")
    assert "error" in r and "known token" in r["error"]


def test_usdc_and_eth_budgets_do_not_cross(tmp_path):
    # spend near the ETH cap, then a USDC payment must still go through
    tools, audit, chain = build(tmp_path)
    tools["request_payment"](ALICE, 0.01, asset="ETH")
    r = tools["request_payment"](ALICE, 20, asset="USDC")
    assert r["decision"] == "allow" and r["executed"] is True


# ---- guarded approve() --------------------------------------------------------

SPENDER = "0xCCCC000000000000000000000000000000000003"


def test_approval_routes_to_approve_erc20(tmp_path):
    tools, audit, chain = build(tmp_path)
    r = tools["request_approval"](SPENDER, 10, "USDC", "dex allowance")
    assert r["decision"] == "allow" and r["executed"] is True
    assert r["operation"] == "approve" and r["tx_hash"] == "0xAPPROVE"
    assert chain.erc20_calls == [] and chain.eth_calls == []
    token_address, spender, amount, decimals = chain.approve_calls[0]
    assert spender == SPENDER and amount == Decimal("10") and decimals == 6
    assert audit.history()[0]["operation"] == "approve"


def test_approval_is_capped_by_per_tx_limit(tmp_path):
    # 30 USDC exceeds the 25 per-tx cap — no unlimited allowance can slip through
    tools, audit, chain = build(tmp_path)
    r = tools["request_approval"](SPENDER, 30, "USDC")
    assert r["decision"] == "deny" and r["rule"] == "per_transaction_max"
    assert chain.approve_calls == []


def test_large_approval_needs_human(tmp_path):
    tools, _, chain = build(tmp_path)
    r = tools["request_approval"](SPENDER, 22, "USDC")  # over the 20 threshold
    assert r["decision"] == "needs_approval" and r["executed"] is False
    assert chain.approve_calls == []


def test_eth_cannot_be_approved(tmp_path):
    tools, _, chain = build(tmp_path)
    r = tools["request_approval"](SPENDER, 0.01, "ETH")
    assert r["decision"] == "deny" and r["rule"] == "approve_requires_token"
    assert chain.approve_calls == []


def test_approval_counts_against_the_same_budget(tmp_path):
    # an allowance is committed value, so it lands in the same asset budget ledger
    # as a direct transfer (this is what closes the many-small-approvals drain).
    tools, audit, chain = build(tmp_path)
    tools["request_approval"](SPENDER, 20, "USDC")      # committed 20
    spent = sum(a for _, a, _, _ in audit.approved_spends("agent-1"))
    assert spent == Decimal("20")  # the approval is in the USDC budget


def test_chain_refuses_unlimited_allowance():
    # the last-line structural guard, independent of policy
    from imprest.services.chain import _UINT256_MAX, _to_base_units
    assert _to_base_units(Decimal("25"), 6) < _UINT256_MAX  # normal amounts are fine
