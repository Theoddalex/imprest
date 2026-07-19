"""Tests for x402 — the pay-per-request HTTP payment path.

The x402 'server' here is an httpx.MockTransport: first request (no X-PAYMENT
header) answers 402 with payment requirements; a request carrying the header is
verified structurally and answered 200 with a settlement receipt. No network,
no chain — but the EIP-3009 signature is REAL and is recovered in the tests to
prove the authorization is exactly what the policy cleared.
"""

from __future__ import annotations

import base64
import json
from decimal import Decimal

import httpx
import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data

from imprest.api.payments import register_payment_tools
from imprest.services.audit import AuditLog
from imprest.services.auth import current_agent_id, current_is_admin
from imprest.services.policy import PolicyStore
from imprest.services.x402 import X402Error, check_url, parse_402

BASE_SEPOLIA = 84532
USDC_ADDR = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"  # registry, Base Sepolia
VENDOR = "0xAAAA000000000000000000000000000000000001"
URL = "https://api.example.com/weather"

DEFAULT = dict(
    per_transaction_max="0.05", daily_max="0.20", hourly_max="0.10",
    rate_limit_per_minute=100, approval_threshold="0.02",
    assets={"USDC": {"per_transaction_max": "25", "hourly_max": "50",
                     "daily_max": "100", "approval_threshold": "5"}},
)

EIP3009_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


class FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


class FakeChain:
    """x402 needs only the signing account — no RPC, no broadcasts."""

    def __init__(self):
        self.account = Account.create()


def fake_resolve(host, port, **kw):
    """Test seam: pretend every hostname resolves to a public IP."""
    return [(2, 1, 6, "", ("93.184.216.34", port))]


def x402_server(price_base_units=1000, pay_to=VENDOR, asset=USDC_ADDR,
                network="base-sepolia", pay_status=200):
    """A fake x402 endpoint. Mutate state to simulate drift / failures:
    state['price'], ['pay_to'], ['asset'], ['pay_status'] are read per request."""
    state = {"price": price_base_units, "pay_to": pay_to, "asset": asset,
             "network": network, "pay_status": pay_status,
             "probes": 0, "payments": []}

    def handler(request: httpx.Request) -> httpx.Response:
        header = request.headers.get("X-PAYMENT")
        if header is None:
            state["probes"] += 1
            return httpx.Response(402, json={
                "x402Version": 1,
                "error": "payment required",
                "accepts": [{
                    "scheme": "exact",
                    "network": state["network"],
                    "maxAmountRequired": str(state["price"]),
                    "resource": str(request.url),
                    "description": "premium weather",
                    "mimeType": "application/json",
                    "payTo": state["pay_to"],
                    "maxTimeoutSeconds": 60,
                    "asset": state["asset"],
                    "extra": {"name": "USDC", "version": "2"},
                }],
            })
        state["payments"].append(json.loads(base64.b64decode(header)))
        if state["pay_status"] != 200:
            # Server accepted the signature (it MAY settle) but replies non-2xx.
            return httpx.Response(state["pay_status"], json={"error": "boom"})
        receipt = base64.b64encode(json.dumps({
            "success": True, "transaction": "0xX402TX", "network": state["network"],
        }).encode()).decode()
        return httpx.Response(200, json={"data": "premium"},
                              headers={"X-PAYMENT-RESPONSE": receipt})

    return handler, state


def build(tmp_path, handler, chain=None, policy=None):
    audit = AuditLog(str(tmp_path / "audit.db"))
    store = PolicyStore(policy or DEFAULT, {})
    mcp = FakeMCP()
    chain = chain or FakeChain()
    register_payment_tools(
        mcp, store, audit,
        get_chain=lambda: chain,
        enable_sends=True, chain_id=BASE_SEPOLIA,
        x402_http=httpx.Client(transport=httpx.MockTransport(handler),
                               follow_redirects=False),
        x402_resolve=fake_resolve,
    )
    return mcp.tools, audit, chain


@pytest.fixture(autouse=True)
def _identity():
    a = current_agent_id.set("agent-1")
    b = current_is_admin.set(True)
    yield
    current_agent_id.reset(a)
    current_is_admin.reset(b)


# ---- the happy path: allow, sign, fetch -----------------------------------------

def test_pay_x402_within_policy_pays_and_returns_the_resource(tmp_path):
    handler, state = x402_server(price_base_units=1000)  # 0.001 USDC
    tools, audit, chain = build(tmp_path, handler)

    r = tools["pay_x402"](URL, max_amount=0.01, reason="weather data")
    assert r["decision"] == "allow" and r["executed"]
    assert r["price"] == "0.001" and r["asset"] == "USDC"
    assert r["tx_hash"] == "0xX402TX"
    assert "premium" in r["body"]

    # The audit row is a real, budget-consuming spend.
    row = audit.history()[0]
    assert row["operation"] == "x402" and row["status"] == "executed"
    assert row["recipient"] == VENDOR and row["amount"] == "0.001"
    spent = sum(a for _, a, _, _ in audit.approved_spends("agent-1"))
    assert spent == Decimal("0.001")


def test_x402_signature_is_a_valid_eip3009_authorization(tmp_path):
    handler, state = x402_server(price_base_units=1000)
    tools, _, chain = build(tmp_path, handler)
    tools["pay_x402"](URL, max_amount=0.01)

    payment = state["payments"][0]
    assert payment["scheme"] == "exact" and payment["x402Version"] == 1
    auth = payment["payload"]["authorization"]
    # exact amount, correct payee, our wallet as payer
    assert auth["value"] == "1000"
    assert auth["to"] == VENDOR
    assert auth["from"] == chain.account.address
    # bounded validity window
    assert int(auth["validBefore"]) - int(auth["validAfter"]) <= 960
    # and the signature recovers to OUR key over the exact typed data
    signable = encode_typed_data(
        domain_data={"name": "USDC", "version": "2", "chainId": BASE_SEPOLIA,
                     "verifyingContract": USDC_ADDR},
        message_types=EIP3009_TYPES,
        message_data={"from": auth["from"], "to": auth["to"],
                      "value": int(auth["value"]),
                      "validAfter": int(auth["validAfter"]),
                      "validBefore": int(auth["validBefore"]),
                      "nonce": auth["nonce"]},
    )
    signer = Account.recover_message(
        signable, signature=payment["payload"]["signature"]
    )
    assert signer == chain.account.address


def test_pay_x402_free_resource_is_just_fetched(tmp_path):
    def handler(request):
        return httpx.Response(200, json={"data": "free"})
    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert r["paid"] is False and r["status"] == 200
    assert json.loads(r["body"]) == {"data": "free"}
    assert audit.history() == []  # nothing to audit: no payment was demanded


# ---- refusals: nothing is ever signed --------------------------------------------

def test_pay_x402_refuses_price_above_the_agents_stated_max(tmp_path):
    handler, state = x402_server(price_base_units=1_000_000)  # 1 USDC
    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert r["decision"] == "deny" and r["rule"] == "x402_price_above_max"
    assert state["payments"] == []
    assert audit.history()[0]["decision"] == "deny"


def test_pay_x402_policy_caps_still_apply(tmp_path):
    handler, state = x402_server(price_base_units=30_000_000)  # 30 USDC > per-tx 25
    tools, _, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=30)
    assert r["decision"] == "deny" and r["rule"] == "per_transaction_max"
    assert state["payments"] == []


def test_pay_x402_unknown_asset_contract_is_unpayable(tmp_path):
    handler, state = x402_server(asset="0xDEAD00000000000000000000000000000000BEEF")
    tools, _, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert r["decision"] == "deny" and r["rule"] == "x402_unpayable"
    assert state["payments"] == []


def test_pay_x402_rejects_non_https_urls(tmp_path):
    handler, state = x402_server()
    tools, _, _ = build(tmp_path, handler)
    r = tools["pay_x402"]("http://169.254.169.254/latest/meta-data", max_amount=0.01)
    assert "error" in r and state["probes"] == 0


# ---- the approval queue works for x402 too ---------------------------------------

def test_x402_above_threshold_freezes_then_approval_completes_the_purchase(tmp_path):
    handler, state = x402_server(price_base_units=6_000_000)  # 6 USDC > threshold 5
    tools, audit, _ = build(tmp_path, handler)

    r = tools["pay_x402"](URL, max_amount=10, reason="bulk dataset")
    assert r["decision"] == "needs_approval" and not r["executed"]
    assert state["payments"] == []          # nothing signed while frozen

    pending = tools["list_pending_approvals"]()["pending"]
    assert pending[0]["context"] == URL     # the operator can see WHAT url
    out = tools["resolve_approval"](pending[0]["id"], approve=True)
    assert out["resolved"] and out["executed"] and out["tx_hash"] == "0xX402TX"
    assert "premium" in out["body"]
    assert len(state["payments"]) == 1
    assert audit.history()[0]["status"] == "executed"


def test_x402_price_hike_after_approval_is_refused_and_stays_pending(tmp_path):
    handler, state = x402_server(price_base_units=6_000_000)
    tools, audit, _ = build(tmp_path, handler)

    r = tools["pay_x402"](URL, max_amount=10)
    pid = r["payment_id"]
    state["price"] = 9_000_000              # server raises the price to 9 USDC

    out = tools["resolve_approval"](pid, approve=True)
    assert out["resolved"] is False and out["executed"] is False
    assert "terms changed" in out["error"]
    assert state["payments"] == []          # the hiked demand was never signed
    # the human's decision isn't burned: the row is pending again
    assert audit.get_pending(pid) is not None


def test_x402_payee_change_after_approval_is_refused_and_stays_pending(tmp_path):
    # The single highest-blast-radius guard: paying the right amount to the
    # WRONG address is total loss. Prove the payee-drift refusal.
    handler, state = x402_server(price_base_units=6_000_000)
    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=10)
    pid = r["payment_id"]
    state["pay_to"] = "0xBBBB000000000000000000000000000000000009"  # attacker swap

    out = tools["resolve_approval"](pid, approve=True)
    assert out["resolved"] is False and out["executed"] is False
    assert "payee" in out["error"]
    assert state["payments"] == []          # nothing signed to the new payee
    assert audit.get_pending(pid) is not None


def test_x402_asset_change_after_approval_is_refused_and_stays_pending(tmp_path):
    # Swapping the asset to an off-registry contract at approval time: parse_402
    # refuses first (unknown contract), which is a pre-send failure -> the row
    # reverts to pending and nothing is signed.
    handler, state = x402_server(price_base_units=6_000_000)  # > threshold 5
    tools, audit, _ = build(tmp_path, handler)
    pid = tools["pay_x402"](URL, max_amount=10)["payment_id"]
    state["asset"] = "0xDEAD00000000000000000000000000000000BEEF"

    out = tools["resolve_approval"](pid, approve=True)
    assert out["resolved"] is False and out["executed"] is False
    assert state["payments"] == []              # nothing signed for the new asset
    assert audit.get_pending(pid) is not None    # decision not burned


def test_x402_mainnet_refuses_localhost(tmp_path):
    # The _allow_local_http gate must be OFF for mainnet chain ids: even a
    # localhost URL is refused (no fetch, no audit row).
    handler, _ = x402_server()
    audit = AuditLog(str(tmp_path / "audit.db"))
    store = PolicyStore(DEFAULT, {})
    mcp = FakeMCP()
    register_payment_tools(
        mcp, store, audit, get_chain=lambda: FakeChain(),
        enable_sends=True, chain_id=8453,          # Base MAINNET
        x402_http=httpx.Client(transport=httpx.MockTransport(handler),
                               follow_redirects=False),
        x402_resolve=fake_resolve,
    )
    r = mcp.tools["pay_x402"]("http://localhost:8080/x", max_amount=0.01)
    assert "error" in r
    assert audit.history() == []


def test_x402_settlement_unknown_counts_budget_and_is_not_retryable(tmp_path):
    # Server ACCEPTS the signature (may settle on-chain) but returns 500. The
    # money may have moved: the row must COUNT toward budget, never be "failed",
    # and never roll back to a free retry with a fresh nonce.
    handler, state = x402_server(price_base_units=1000, pay_status=500)
    tools, audit, _ = build(tmp_path, handler)

    r = tools["pay_x402"](URL, max_amount=0.01)
    assert r["decision"] == "allow" and r["executed"] is False
    assert r["error"] and "settlement unknown" in r["error"]
    assert len(state["payments"]) == 1              # the signature WAS sent

    row = audit.history()[0]
    assert row["status"] == "settlement_unknown"
    # counts toward the budget even though HTTP "failed"
    spent = sum(a for _, a, _, _ in audit.approved_spends("agent-1"))
    assert spent == Decimal("0.001")


def test_x402_retry_after_settlement_unknown_reuses_the_same_nonce(tmp_path):
    # Approval path: a settlement-unknown must be terminal (not reverted to
    # pending), and if re-attempted the nonce is identical (idempotent auth).
    handler, state = x402_server(price_base_units=6_000_000, pay_status=502)
    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=10)
    pid = r["payment_id"]

    out = tools["resolve_approval"](pid, approve=True)
    assert out["decision"] == "settlement_unknown" and out["resolved"] is True
    assert audit.get_pending(pid) is None           # terminal, not re-pending
    row = audit.history()[0]
    assert row["status"] == "settlement_unknown"
    nonce1 = state["payments"][0]["payload"]["authorization"]["nonce"]

    # Even if the same logical payment were signed again, the nonce is stable.
    from imprest.services.x402 import payment_nonce
    assert payment_nonce(f"agent-1:{pid}") == nonce1


def test_x402_goes_free_between_quote_and_pay_consumes_no_budget(tmp_path):
    # 402 on the probe, then 200 (free) on the in-lock re-fetch: no payment is
    # made, so budget must NOT be debited and nothing is signed.
    state = {"probed": False}

    def handler(request):
        if request.headers.get("X-PAYMENT") is not None:
            return httpx.Response(200, json={"data": "now free"})
        if not state["probed"]:
            state["probed"] = True
            return httpx.Response(402, json={
                "x402Version": 1, "accepts": [{
                    "scheme": "exact", "network": "base-sepolia",
                    "maxAmountRequired": "1000", "payTo": VENDOR,
                    "asset": USDC_ADDR, "maxTimeoutSeconds": 60}]})
        return httpx.Response(200, json={"data": "now free"})  # re-fetch is free

    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert r["executed"] is False and r.get("paid") is False
    assert sum(a for _, a, _, _ in audit.approved_spends("agent-1")) == Decimal("0")
    assert audit.history()[0]["status"] == "skipped"


def test_x402_signing_error_marks_failed_and_no_budget(tmp_path):
    handler, state = x402_server(price_base_units=1000)

    class BrokenChain:
        @property
        def account(self):
            raise RuntimeError("keystore locked")

    tools, audit, _ = build(tmp_path, handler, chain=BrokenChain())
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert r["executed"] is False and r["error"]
    assert state["payments"] == []                  # never got to sign/send
    assert audit.history()[0]["status"] == "failed"
    assert audit.approved_spends("agent-1") == []


def test_pay_x402_rejects_malformed_json_body(tmp_path):
    def handler(request):
        return httpx.Response(402, text="<html>not json</html>")
    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert r["decision"] == "deny" and r["rule"] == "x402_unpayable"


def test_pay_x402_validates_max_amount(tmp_path):
    handler, state = x402_server()
    tools, audit, _ = build(tmp_path, handler)
    for bad in (0, -1, float("nan"), float("inf")):
        r = tools["pay_x402"](URL, max_amount=bad)
        assert "error" in r, bad
    # Rejected at the boundary: never probed, never recorded, never signed.
    assert state["probes"] == 0
    assert audit.history() == []


def test_pay_x402_network_error_on_probe_is_clean(tmp_path):
    def handler(request):
        raise httpx.ConnectError("refused")
    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert "error" in r
    assert audit.history() == []                     # nothing recorded


def test_pay_x402_refuses_redirect_to_internal_host(tmp_path):
    # A vetted public host 302s to cloud metadata; the guard must re-run on the
    # hop and refuse — the whole point of manual redirect following.
    def handler(request):
        return httpx.Response(302, headers={
            "location": "https://169.254.169.254/latest/meta-data"})
    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"]("https://vendor.example.com/x", max_amount=0.01)
    assert "error" in r and "refus" in r["error"].lower()
    assert audit.history() == []


def test_pay_x402_refuses_oversized_body(tmp_path):
    # Streamed in many chunks so the cap must abort mid-stream, not post-buffer.
    def handler(request):
        def body():
            for _ in range(400):
                yield b"x" * 1024
        return httpx.Response(402, stream=body())
    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert "error" in r
    assert audit.history() == []                 # nothing recorded


def test_x402_network_blip_after_signature_is_settlement_unknown(tmp_path):
    # The signature is transmitted, then the connection dies mid-response. Funds
    # may have moved -> settlement_unknown (counts budget), not failed.
    state = {"paid_seen": False}

    def handler(request):
        if request.headers.get("X-PAYMENT") is not None:
            state["paid_seen"] = True
            raise httpx.ReadError("connection reset after send")
        return httpx.Response(402, json={
            "x402Version": 1, "accepts": [{
                "scheme": "exact", "network": "base-sepolia",
                "maxAmountRequired": "1000", "payTo": VENDOR,
                "asset": USDC_ADDR, "maxTimeoutSeconds": 60}]})

    tools, audit, _ = build(tmp_path, handler)
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert state["paid_seen"] and r["executed"] is False
    assert "settlement unknown" in r["error"]
    assert audit.history()[0]["status"] == "settlement_unknown"
    assert sum(a for _, a, _, _ in audit.approved_spends("agent-1")) == Decimal("0.001")


def test_x402_validity_window_is_clamped_regardless_of_server_timeout(tmp_path):
    # Server asks for a 1-day window; we must cap it at _MAX_VALIDITY_SECONDS.
    handler, state = x402_server(price_base_units=1000)
    state["_"] = None
    # Patch the offer's maxTimeoutSeconds via a custom handler.
    def handler2(request):
        if request.headers.get("X-PAYMENT") is not None:
            state["payments"].append(json.loads(
                base64.b64decode(request.headers["X-PAYMENT"])))
            receipt = base64.b64encode(json.dumps(
                {"transaction": "0xX402TX"}).encode()).decode()
            return httpx.Response(200, json={"data": "ok"},
                                  headers={"X-PAYMENT-RESPONSE": receipt})
        return httpx.Response(402, json={
            "x402Version": 1, "accepts": [{
                "scheme": "exact", "network": "base-sepolia",
                "maxAmountRequired": "1000", "payTo": VENDOR,
                "asset": USDC_ADDR, "maxTimeoutSeconds": 86400}]})  # 1 day
    tools, _, _ = build(tmp_path, handler2)
    tools["pay_x402"](URL, max_amount=0.01)
    auth = state["payments"][0]["payload"]["authorization"]
    assert int(auth["validBefore"]) - int(auth["validAfter"]) <= 60 + 900


def test_x402_unknown_recipient_ask_mode_freezes_the_endpoint_payment(tmp_path):
    # allowlist set (to someone else) + ask mode: a NEW x402 payee escalates.
    handler, state = x402_server(price_base_units=1000)
    policy = {**DEFAULT,
              "allowlist": ["0xbbbb000000000000000000000000000000000002"],
              "unknown_recipient": "ask"}
    tools, _, _ = build(tmp_path, handler, policy=policy)
    r = tools["pay_x402"](URL, max_amount=0.01)
    assert r["decision"] == "needs_approval"
    assert r["rule"] == "allowlist_unknown_recipient"
    assert state["payments"] == []


# ---- parsing / URL guard unit tests ----------------------------------------------

def _requirement(**overrides):
    base = {
        "scheme": "exact", "network": "base-sepolia",
        "maxAmountRequired": "1000", "payTo": VENDOR, "asset": USDC_ADDR,
        "maxTimeoutSeconds": 60, "extra": {"name": "USDC", "version": "2"},
    }
    base.update(overrides)
    return base


def test_parse_402_accepts_caip2_network_names():
    offer = parse_402(
        {"x402Version": 1, "accepts": [_requirement(network="eip155:84532")]},
        BASE_SEPOLIA,
    )
    assert offer.amount == Decimal("0.001") and offer.asset_symbol == "USDC"


def test_parse_402_rejects_other_networks():
    with pytest.raises(X402Error, match="no satisfiable"):
        parse_402({"accepts": [_requirement(network="base")]}, BASE_SEPOLIA)


def test_parse_402_rejects_negative_amounts():
    with pytest.raises(X402Error, match="negative"):
        parse_402({"accepts": [_requirement(maxAmountRequired="-5")]}, BASE_SEPOLIA)


def test_parse_402_picks_the_matching_offer_among_several():
    offers = [_requirement(network="base", asset="0x" + "11" * 20),
              _requirement()]
    offer = parse_402({"accepts": offers}, BASE_SEPOLIA)
    assert offer.pay_to == VENDOR


def test_check_url_guard():
    # Public host (fake resolver) passes; localhost http passes only with the flag.
    assert check_url("https://api.example.com/x", resolve=fake_resolve) is None
    assert check_url("http://localhost:8080/x", allow_local=True) is None
    assert check_url("http://localhost:8080/x") is not None  # http needs the flag
    assert check_url("http://internal.corp/secrets", resolve=fake_resolve) is not None
    assert check_url("ftp://example.com", resolve=fake_resolve) is not None


def test_check_url_blocks_private_and_metadata_ips():
    # Bare IP literals are vetted directly, no DNS needed.
    for bad in ("https://169.254.169.254/latest/meta-data",   # cloud metadata
                "https://127.0.0.1/x", "https://10.0.0.5/x",
                "https://192.168.1.1/x", "https://[::1]/x",
                "https://100.64.1.1/x",                        # CGNAT (RFC 6598)
                "https://[::ffff:169.254.169.254]/x",          # v4-mapped v6
                "https://[::ffff:127.0.0.1]/x"):
        assert check_url(bad) is not None, bad
    # A hostname that RESOLVES to a private address is refused too.
    def resolve_to_private(host, port, **kw):
        return [(2, 1, 6, "", ("169.254.169.254", port))]
    assert check_url("https://sneaky.example.com/x",
                     resolve=resolve_to_private) is not None
    # ...including when it resolves to a v4-mapped-v6 metadata address.
    def resolve_to_mapped(host, port, **kw):
        return [(2, 1, 6, "", ("::ffff:169.254.169.254", port))]
    assert check_url("https://sneaky2.example.com/x",
                     resolve=resolve_to_mapped) is not None
