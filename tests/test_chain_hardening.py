"""Mainnet-hardening tests for the chain layer.

The RPC endpoint is untrusted: these tests prove that a lying/broken RPC
cannot make us overpay gas, that concurrent sends can't collide on a nonce,
and that a transaction is only ever reported as a success once it is mined
with status=1. All chain interaction goes through a FakeW3 stub — no network.
"""

from __future__ import annotations

import threading
import time
from decimal import Decimal

import pytest

from imprest.services.chain import Chain

GWEI = 10**9
TOKEN = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
ALICE = "0xAAAA000000000000000000000000000000000001"


class FakeHash:
    def __init__(self, h: str):
        self._h = h

    def hex(self) -> str:
        return self._h


class FakeBoundFn:
    """Stands in for contract.functions.transfer(...) / balanceOf(...) etc."""

    def __init__(self, name, args, eth):
        self.name, self.args, self.eth = name, args, eth

    def build_transaction(self, params: dict) -> dict:
        return {**params, "data": (self.name, self.args)}

    def call(self):                          # read path (balanceOf preflight)
        return self.eth.token_balance


class FakeFunctions:
    def __init__(self, eth):
        self._eth = eth

    def __getattr__(self, name):
        return lambda *args: FakeBoundFn(name, args, self._eth)


class FakeContract:
    def __init__(self, eth):
        self.functions = FakeFunctions(eth)


class FakeEth:
    """The RPC surface Chain touches, with a controllable pending count."""

    def __init__(self, gas_price=1 * GWEI, receipt_status=1, nonce_read_delay=0.0):
        self.gas_price = gas_price
        self.receipt_status = receipt_status
        self.nonce_read_delay = nonce_read_delay
        self.balance = 10**21                # plenty of ETH unless a test says otherwise
        self.token_balance = 10**30          # plenty of tokens, likewise
        self.sent: list[dict] = []           # every broadcast tx dict
        self.nonce_blocks: list = []         # block identifier used per nonce read
        self.wait_raises: Exception | None = None

    def get_balance(self, address):
        return self.balance

    def get_transaction_count(self, address, block_identifier=None):
        self.nonce_blocks.append(block_identifier)
        count = len(self.sent)               # pending = everything broadcast so far
        # widen the read->broadcast race window so an unlocked implementation
        # would deterministically hand two concurrent senders the same nonce
        time.sleep(self.nonce_read_delay)
        return count

    def send_raw_transaction(self, raw):
        self.sent.append(raw)                # raw IS the tx dict (see FakeAccount)
        return FakeHash(f"0xtx{len(self.sent)}")

    def wait_for_transaction_receipt(self, tx_hash, timeout=None):
        if self.wait_raises:
            raise self.wait_raises
        return {"status": self.receipt_status}

    def contract(self, address=None, abi=None):
        return FakeContract(self)


class FakeW3:
    def __init__(self, eth: FakeEth):
        self.eth = eth

    @staticmethod
    def to_wei(value, unit):
        scale = {"gwei": 10**9, "ether": 10**18}[unit]
        return int(Decimal(str(value)) * scale)

    @staticmethod
    def from_wei(value, unit):
        scale = {"gwei": 10**9, "ether": 10**18}[unit]
        return Decimal(value) / scale

    @staticmethod
    def to_checksum_address(addr):
        return addr


class FakeSigned:
    def __init__(self, tx):
        self.raw_transaction = tx            # pass the tx dict through untouched


class FakeAccount:
    address = "0xWALLET00000000000000000000000000000000001"

    def sign_transaction(self, tx):
        return FakeSigned(tx)


def make_chain(gas_price=1 * GWEI, max_fee_gwei="50", nonce_read_delay=0.0, **kw) -> tuple[Chain, FakeEth]:
    eth = FakeEth(gas_price=gas_price, nonce_read_delay=nonce_read_delay)
    chain = Chain("http://127.0.0.1:1", 8453, account=FakeAccount(),
                  max_fee_gwei=Decimal(max_fee_gwei), **kw)
    chain.w3 = FakeW3(eth)                   # never touches the real provider
    return chain, eth


# ---- fee ceiling: the RPC's gas quote is untrusted --------------------------

def test_gas_quote_above_ceiling_refuses_to_sign():
    chain, eth = make_chain(gas_price=400 * GWEI, max_fee_gwei="50")
    with pytest.raises(RuntimeError, match="refusing to sign"):
        chain.send_eth(ALICE, Decimal("0.001"))
    assert eth.sent == []                    # nothing was broadcast

def test_fee_headroom_is_capped_at_ceiling():
    # quote 30 gwei -> 2x headroom would be 60, but the 50 gwei ceiling wins
    chain, eth = make_chain(gas_price=30 * GWEI, max_fee_gwei="50")
    chain.send_eth(ALICE, Decimal("0.001"))
    assert eth.sent[0]["maxFeePerGas"] == 50 * GWEI

def test_normal_quote_gets_double_headroom():
    chain, eth = make_chain(gas_price=2 * GWEI, max_fee_gwei="50")
    chain.send_eth(ALICE, Decimal("0.001"))
    assert eth.sent[0]["maxFeePerGas"] == 4 * GWEI


# ---- gas limits: fixed from config, never estimated via the RPC -------------

def test_erc20_gas_limit_is_fixed_from_config():
    chain, eth = make_chain(erc20_gas_limit=99_000)
    chain.send_erc20(TOKEN, ALICE, Decimal("10"), 6)
    tx = eth.sent[0]
    assert tx["gas"] == 99_000
    assert tx["data"][0] == "transfer"

def test_approve_uses_fixed_gas_limit_too():
    chain, eth = make_chain(erc20_gas_limit=99_000)
    chain.approve_erc20(TOKEN, ALICE, Decimal("10"), 6)
    assert eth.sent[0]["gas"] == 99_000
    assert eth.sent[0]["data"][0] == "approve"


# ---- nonces: pending count + per-wallet lock ---------------------------------

def test_nonce_reads_use_pending_block():
    chain, eth = make_chain()
    chain.send_eth(ALICE, Decimal("0.001"))
    assert eth.nonce_blocks == ["pending"]

def test_rapid_sequential_sends_get_sequential_nonces():
    chain, eth = make_chain()
    chain.send_eth(ALICE, Decimal("0.001"))
    chain.send_eth(ALICE, Decimal("0.001"))
    assert [tx["nonce"] for tx in eth.sent] == [0, 1]

def test_concurrent_sends_from_same_wallet_do_not_collide():
    # the fake delays inside the nonce read, so WITHOUT the wallet lock both
    # threads would read nonce 0 and the second tx would replace the first
    chain, eth = make_chain(nonce_read_delay=0.05)
    t1 = threading.Thread(target=chain.send_eth, args=(ALICE, Decimal("0.001")))
    t2 = threading.Thread(target=chain.send_eth, args=(ALICE, Decimal("0.001")))
    t1.start(); t2.start(); t1.join(); t2.join()
    assert sorted(tx["nonce"] for tx in eth.sent) == [0, 1]


# ---- balance preflight: fail with "top up", not a burned-gas revert ----------

def test_insufficient_eth_refuses_before_broadcast():
    chain, eth = make_chain()
    eth.balance = 0
    with pytest.raises(RuntimeError, match="insufficient ETH.*top up"):
        chain.send_eth(ALICE, Decimal("0.001"))
    assert eth.sent == []

def test_insufficient_token_balance_refuses_before_broadcast():
    chain, eth = make_chain()
    eth.token_balance = 5_000_000           # 5 USDC in base units
    with pytest.raises(RuntimeError, match="insufficient token.*top up"):
        chain.send_erc20(TOKEN, ALICE, Decimal("10"), 6)
    assert eth.sent == []

def test_approve_needs_gas_but_not_token_balance():
    # granting an allowance moves no tokens, so an empty token balance is fine
    chain, eth = make_chain()
    eth.token_balance = 0
    chain.approve_erc20(TOKEN, ALICE, Decimal("10"), 6)
    assert len(eth.sent) == 1


# ---- confirmation: broadcast is not success ----------------------------------

def test_reverted_tx_raises_instead_of_returning_hash():
    chain, eth = make_chain()
    eth.receipt_status = 0
    with pytest.raises(RuntimeError, match="reverted"):
        chain.send_erc20(TOKEN, ALICE, Decimal("10"), 6)

def test_unconfirmed_tx_raises_with_the_hash():
    chain, eth = make_chain()
    eth.wait_raises = TimeoutError("timed out")
    with pytest.raises(RuntimeError, match="0xtx1.*unconfirmed"):
        chain.send_eth(ALICE, Decimal("0.001"))

def test_confirmed_tx_returns_hash():
    chain, eth = make_chain()
    assert chain.send_eth(ALICE, Decimal("0.001")) == "0xtx1"


# ---- mainnet token registry ---------------------------------------------------

def test_mainnet_usdc_entries_exist():
    from imprest.services.tokens import token_for
    base = token_for(8453, "USDC")
    l1 = token_for(1, "USDC")
    assert base.address == "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    assert base.decimals == 6
    assert l1.address == "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    assert l1.decimals == 6
