"""Ethereum layer — thin web3.py wrapper.

Read methods (balance, gas) are always safe. The write methods (send_eth,
send_erc20, approve_erc20) are the only things that can move funds, and they
are only ever called AFTER the policy engine has returned ALLOW — never
directly by the agent.

Mainnet hardening — the RPC endpoint is treated as UNTRUSTED:
  * Fee ceiling: the RPC quotes the gas price, but we never sign above the
    configured `max_fee_gwei`. A malicious/broken RPC cannot make us overpay.
  * Fixed gas limits: 21_000 for ETH, `erc20_gas_limit` for token calls — we
    never ask the RPC to estimate gas, so it cannot inflate the limit either.
    Worst-case gas cost is therefore bounded: gas_limit x max_fee, always.
  * Pending nonce + per-wallet lock: rapid or concurrent sends from the same
    wallet get sequential nonces instead of silently replacing each other.
  * Receipt confirmation: a send only returns once the tx is mined with
    status=1. Reverts and confirmation timeouts raise, so the audit log never
    records a failed transaction as executed.

web3 is imported lazily so the pure policy layer stays dependency-free.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from decimal import Decimal

# Minimal ERC-20 ABI — only the methods agentmandate touches. approve() is included
# for the GUARDED approval path: agentmandate only ever approves an exact, finite
# amount (never the unlimited 2**256-1 allowance that is behind most token
# drains), and only after the policy engine clears it.
_ERC20_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "_owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "balance", "type": "uint256"}],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "transfer",
        "outputs": [{"name": "success", "type": "bool"}],
        "type": "function",
    },
    {
        "constant": False,
        "inputs": [
            {"name": "_spender", "type": "address"},
            {"name": "_value", "type": "uint256"},
        ],
        "name": "approve",
        "outputs": [{"name": "success", "type": "bool"}],
        "type": "function",
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function",
    },
]

# An ERC-20 allowance at or near this is effectively "unlimited" — the pattern
# behind most wallet drains. agentmandate must never sign one; the policy per-tx cap
# already blocks large amounts, this is the last-line structural refusal.
_UINT256_MAX = 2**256 - 1

# One lock per wallet address, module-level: a fresh Chain is constructed per
# tool call (see application.get_chain), so the lock must outlive any instance.
# It serialises the nonce-fetch -> sign -> broadcast window; without it, two
# concurrent sends read the same nonce and the later tx replaces the earlier.
_wallet_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)


def _to_base_units(amount: Decimal, decimals: int) -> int:
    """Whole token units -> integer base units, exactly (no float).

    USDC has 6 decimals, so 50 USDC -> 50_000_000. Any fractional part finer
    than the token's precision is a bug in the caller, so we refuse it rather
    than silently truncate.
    """
    scaled = amount * (Decimal(10) ** decimals)
    if scaled != scaled.to_integral_value():
        raise ValueError(
            f"amount {amount} has more precision than the token's {decimals} decimals"
        )
    return int(scaled)


class Chain:
    def __init__(
        self,
        rpc_url: str,
        chain_id: int,
        account=None,
        max_fee_gwei: Decimal = Decimal("50"),
        erc20_gas_limit: int = 120_000,
        receipt_timeout: int = 120,
    ) -> None:
        from web3 import Web3

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.chain_id = chain_id
        self.account = account
        self.max_fee_gwei = Decimal(max_fee_gwei)
        self.erc20_gas_limit = erc20_gas_limit
        self.receipt_timeout = receipt_timeout

    def is_connected(self) -> bool:
        return self.w3.is_connected()

    def get_balance(self, address: str) -> Decimal:
        """ETH balance of an address."""
        checksum = self.w3.to_checksum_address(address)
        wei = self.w3.eth.get_balance(checksum)
        return Decimal(self.w3.from_wei(wei, "ether"))

    def gas_price_gwei(self) -> Decimal:
        return Decimal(self.w3.from_wei(self.w3.eth.gas_price, "gwei"))

    def get_token_balance(self, token_address: str, address: str, decimals: int) -> Decimal:
        """ERC-20 balance of an address, in whole token units (read-only)."""
        contract = self.w3.eth.contract(
            address=self.w3.to_checksum_address(token_address), abi=_ERC20_ABI
        )
        raw = contract.functions.balanceOf(
            self.w3.to_checksum_address(address)
        ).call()
        return Decimal(raw) / (Decimal(10) ** decimals)

    def _fees(self) -> tuple[int, int]:
        """(maxFeePerGas, maxPriorityFeePerGas) — RPC quote capped at the ceiling.

        The quote is doubled for headroom against short-term spikes, but the
        result never exceeds `max_fee_gwei`. If the quote ITSELF is already
        above the ceiling the network is either congested beyond what the
        operator budgeted for or the RPC is lying — either way we refuse to
        sign rather than overpay.
        """
        ceiling = self.w3.to_wei(self.max_fee_gwei, "gwei")
        quoted = self.w3.eth.gas_price
        if quoted > ceiling:
            raise RuntimeError(
                f"gas price {self.w3.from_wei(quoted, 'gwei')} gwei exceeds the "
                f"configured max_fee_gwei ceiling ({self.max_fee_gwei} gwei); "
                "refusing to sign"
            )
        max_fee = min(quoted * 2, ceiling)
        # priority fee must never exceed max fee (invalid tx when base fee is
        # tiny, e.g. on quiet testnets); clamp it.
        priority_fee = min(self.w3.to_wei(1, "gwei"), max_fee)
        return max_fee, priority_fee

    def _sign_send_confirm(self, build_tx) -> str:
        """The single broadcast path: lock -> pending nonce -> sign -> send -> confirm.

        `build_tx(nonce)` returns the ready-to-sign tx dict. The wallet lock
        covers nonce-fetch through broadcast (so concurrent senders sharing
        this wallet queue up instead of colliding); the confirmation wait
        happens OUTSIDE the lock — once broadcast, the pending count already
        includes this tx, so the next sender gets the right nonce.
        """
        with _wallet_locks[self.account.address]:
            nonce = self.w3.eth.get_transaction_count(self.account.address, "pending")
            signed = self.account.sign_transaction(build_tx(nonce))
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)

        h = tx_hash.hex()
        try:
            receipt = self.w3.eth.wait_for_transaction_receipt(
                tx_hash, timeout=self.receipt_timeout
            )
        except Exception as e:
            # Broadcast but unconfirmed: the tx MAY still land later. Surface
            # the hash so the operator can check; the audit row records this
            # as failed, which over-counts spend — the safe direction.
            raise RuntimeError(
                f"tx {h} broadcast but unconfirmed after {self.receipt_timeout}s "
                f"({e}); check the explorer before retrying"
            ) from e
        if receipt["status"] != 1:
            raise RuntimeError(f"tx {h} reverted on-chain")
        return h

    def _preflight_gas(self, max_fee: int, gas_limit: int, extra_wei: int = 0) -> None:
        """Refuse cleanly when the wallet can't cover worst-case gas (+ value).

        A doomed transaction would either be rejected by the node or, worse,
        revert on-chain and burn its gas. Checking first turns "cryptic
        failure" into "top up the wallet" — the prepaid card's empty state.
        """
        balance = self.w3.eth.get_balance(self.account.address)
        needed = gas_limit * max_fee + extra_wei
        if balance < needed:
            raise RuntimeError(
                f"insufficient ETH for gas: wallet {self.account.address} holds "
                f"{self.w3.from_wei(balance, 'ether')} ETH, needs up to "
                f"{self.w3.from_wei(needed, 'ether')} — top up the wallet"
            )

    def send_eth(self, to: str, amount_eth: Decimal) -> str:
        """Sign, broadcast and CONFIRM an ETH transfer. Returns the tx hash.

        Precondition: caller has already cleared this with the policy engine.
        """
        if self.account is None:
            raise RuntimeError("no account loaded; cannot send")

        to_checksum = self.w3.to_checksum_address(to)
        max_fee, priority_fee = self._fees()
        self._preflight_gas(max_fee, 21_000,
                            extra_wei=self.w3.to_wei(amount_eth, "ether"))
        return self._sign_send_confirm(lambda nonce: {
            "to": to_checksum,
            "value": self.w3.to_wei(amount_eth, "ether"),
            "nonce": nonce,
            "gas": 21_000,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": priority_fee,
            "chainId": self.chain_id,
        })

    def _erc20_call(
        self, token_address: str, fn_name: str, args: tuple,
        token_amount: int | None = None,
    ) -> str:
        """Build, sign, broadcast and confirm an ERC-20 state-changing call.

        The gas limit is FIXED from config, never estimated via the RPC — a
        hostile endpoint can therefore neither inflate the limit nor the price
        (see _fees). If the fixed limit is too small the tx reverts out-of-gas
        and _sign_send_confirm raises: fail-closed, never fail-expensive.

        `token_amount` (base units) triggers a token-balance preflight — set
        for transfer (which moves tokens), not for approve (which doesn't).
        """
        if self.account is None:
            raise RuntimeError("no account loaded; cannot send")

        contract = self.w3.eth.contract(
            address=self.w3.to_checksum_address(token_address), abi=_ERC20_ABI
        )
        max_fee, priority_fee = self._fees()
        self._preflight_gas(max_fee, self.erc20_gas_limit)
        if token_amount is not None:
            held = contract.functions.balanceOf(self.account.address).call()
            if held < token_amount:
                raise RuntimeError(
                    f"insufficient token balance: wallet {self.account.address} "
                    f"holds {held} base units, needs {token_amount} — top up the wallet"
                )
        return self._sign_send_confirm(
            lambda nonce: getattr(contract.functions, fn_name)(*args).build_transaction(
                {
                    "from": self.account.address,
                    "nonce": nonce,
                    "gas": self.erc20_gas_limit,
                    "maxFeePerGas": max_fee,
                    "maxPriorityFeePerGas": priority_fee,
                    "chainId": self.chain_id,
                }
            )
        )

    def approve_erc20(
        self, token_address: str, spender: str, amount: Decimal, decimals: int
    ) -> str:
        """Grant `spender` an allowance of exactly `amount` tokens. Returns the tx hash.

        This is the guarded approval: the amount is an exact, finite value (in
        whole token units) — never the unlimited allowance. If the computed base
        amount ever reached the uint256 ceiling we refuse to sign, as a last-line
        structural guard on top of the policy per-transaction cap.

        Precondition: caller has already cleared this with the policy engine.
        """
        value = _to_base_units(amount, decimals)
        if value >= _UINT256_MAX:
            raise ValueError("refusing to sign an unlimited (uint256-max) allowance")
        return self._erc20_call(
            token_address, "approve", (self.w3.to_checksum_address(spender), value)
        )

    def send_erc20(
        self, token_address: str, to: str, amount: Decimal, decimals: int
    ) -> str:
        """Sign, broadcast and CONFIRM an ERC-20 transfer. Returns the tx hash.

        `amount` is in whole token units (e.g. 50 for 50 USDC); it is converted
        to base units using the token's own `decimals`. This calls transfer()
        only — no approve(), so no allowance is ever granted.

        Precondition: caller has already cleared this with the policy engine.
        """
        value = _to_base_units(amount, decimals)
        return self._erc20_call(
            token_address, "transfer", (self.w3.to_checksum_address(to), value),
            token_amount=value,
        )
