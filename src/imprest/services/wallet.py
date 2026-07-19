"""Wallet key management — the agent's dedicated "prepaid card" wallet.

The key is generated LOCALLY from OS entropy (`eth_account.Account.create()`
-> os.urandom) and never leaves this machine. The model: a fresh wallet is
born for the agent, the owner funds it with only what the agent may spend,
and the owner's real wallet never touches imprest at all.

Creation is an explicit ceremony (`imprest init` -> create_account), not a
side effect. On TESTNETS a missing key may still be auto-created at first use
(zero-config demos); on MAINNET chains a missing key is an error — real-money
keys must only come into existence when a human asks for one.

web3/eth_account are imported lazily so the pure layers (policy, schemas) and
their tests don't require them installed.
"""

from __future__ import annotations

import os

# Chains where funds are real. On these, keys are never created implicitly.
MAINNET_CHAIN_IDS = {1, 8453}


def create_account(keystore_path: str, private_key: str | None = None):
    """Explicitly create (or import) the wallet at keystore_path.

    Refuses to overwrite an existing key — a funded wallet must never be
    silently replaced. The file is created 0600 atomically (O_EXCL), so there
    is no window where another local user could read or race it.
    """
    from eth_account import Account

    acct = Account.from_key(private_key) if private_key else Account.create()
    fd = os.open(keystore_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(acct.key.hex())
    return acct


def load_account(keystore_path: str):
    """Load the existing wallet, or fail with the fix spelled out."""
    from eth_account import Account

    if not os.path.exists(keystore_path):
        raise FileNotFoundError(
            f"no wallet at {keystore_path} — run `imprest init` to create one"
        )
    with open(keystore_path) as f:
        return Account.from_key(f.read().strip())


def load_or_create_account(keystore_path: str, chain_id: int | None = None):
    """Load the wallet, auto-creating it on TESTNETS only.

    Auto-creation keeps the zero-config testnet demo (`enable_sends=true`,
    no setup, play money). On a mainnet chain a missing key is refused:
    creating a real-money wallet must be the operator's explicit act.
    """
    if os.path.exists(keystore_path):
        return load_account(keystore_path)
    if chain_id in MAINNET_CHAIN_IDS:
        raise RuntimeError(
            f"no wallet at {keystore_path}, and chain {chain_id} is a mainnet — "
            "refusing to silently create a real-money wallet. "
            "Run `imprest init` first."
        )
    return create_account(keystore_path)
