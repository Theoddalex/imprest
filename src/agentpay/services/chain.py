"""Ethereum layer — thin web3.py wrapper, Sepolia testnet.

Read methods (balance, gas) are always safe. The single write method (send_eth)
is the only thing that can move funds, and it is only ever called AFTER the
policy engine has returned ALLOW — never directly by the agent.

web3 is imported lazily so the pure policy layer stays dependency-free.
"""

from __future__ import annotations

from decimal import Decimal


class Chain:
    def __init__(self, rpc_url: str, chain_id: int, account=None) -> None:
        from web3 import Web3

        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.chain_id = chain_id
        self.account = account

    def is_connected(self) -> bool:
        return self.w3.is_connected()

    def get_balance(self, address: str) -> Decimal:
        """ETH balance of an address."""
        checksum = self.w3.to_checksum_address(address)
        wei = self.w3.eth.get_balance(checksum)
        return Decimal(self.w3.from_wei(wei, "ether"))

    def gas_price_gwei(self) -> Decimal:
        return Decimal(self.w3.from_wei(self.w3.eth.gas_price, "gwei"))

    def send_eth(self, to: str, amount_eth: Decimal) -> str:
        """Sign and broadcast an ETH transfer. Returns the tx hash.

        Precondition: caller has already cleared this with the policy engine.
        """
        if self.account is None:
            raise RuntimeError("no account loaded; cannot send")

        to_checksum = self.w3.to_checksum_address(to)
        tx = {
            "to": to_checksum,
            "value": self.w3.to_wei(amount_eth, "ether"),
            "nonce": self.w3.eth.get_transaction_count(self.account.address),
            "gas": 21_000,
            "maxFeePerGas": self.w3.eth.gas_price * 2,
            "maxPriorityFeePerGas": self.w3.to_wei(1, "gwei"),
            "chainId": self.chain_id,
        }
        signed = self.account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        return tx_hash.hex()
