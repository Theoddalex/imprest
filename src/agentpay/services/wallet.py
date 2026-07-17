"""Throwaway wallet management — TESTNET ONLY.

Generates/loads a local private key for the agent to sign Sepolia transactions.
web3 is imported lazily so the pure layers (policy, schemas) and their tests
don't require it installed.

SECURITY: this key is for testnet play money. Never put a mainnet key with real
funds behind an autonomous agent — the whole product exists because agents are
probabilistic and you must assume they will occasionally do the wrong thing.
"""

from __future__ import annotations

import os


def load_or_create_account(keystore_path: str):
    """Return an eth_account.Account for the key at keystore_path, creating one if absent."""
    from eth_account import Account

    if os.path.exists(keystore_path):
        with open(keystore_path) as f:
            private_key = f.read().strip()
        return Account.from_key(private_key)

    acct = Account.create()
    with open(keystore_path, "w") as f:
        f.write(acct.key.hex())
    os.chmod(keystore_path, 0o600)  # owner-only
    return acct
