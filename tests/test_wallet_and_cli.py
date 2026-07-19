"""Wallet lifecycle rules + the operator CLI (init / status).

The rules under test:
  * key creation is explicit — mainnet never auto-creates, testnet may
  * an existing (possibly funded) wallet is never overwritten
  * `init` is idempotent and always surfaces the funding address
  * `status` degrades gracefully (no wallet / no RPC) instead of crashing
"""

from __future__ import annotations

import os
import stat

import pytest

from imprest.services.wallet import (
    MAINNET_CHAIN_IDS,
    create_account,
    load_account,
    load_or_create_account,
)

BASE_MAINNET = 8453
BASE_SEPOLIA = 84532


# ---- key lifecycle -------------------------------------------------------------

def test_create_then_load_roundtrips_the_address(tmp_path):
    path = str(tmp_path / "wallet.key")
    created = create_account(path)
    assert load_account(path).address == created.address

def test_keyfile_is_owner_only(tmp_path):
    path = str(tmp_path / "wallet.key")
    create_account(path)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600

def test_create_refuses_to_overwrite_existing_wallet(tmp_path):
    path = str(tmp_path / "wallet.key")
    create_account(path)
    with pytest.raises(FileExistsError):
        create_account(path)

def test_import_existing_key(tmp_path):
    path = str(tmp_path / "wallet.key")
    donor = create_account(str(tmp_path / "donor.key"))
    imported = create_account(path, private_key=donor.key.hex())
    assert imported.address == donor.address

def test_load_missing_wallet_names_the_fix(tmp_path):
    with pytest.raises(FileNotFoundError, match="imprest init"):
        load_account(str(tmp_path / "nope.key"))


# ---- the mainnet guard -----------------------------------------------------------

def test_testnet_still_autocreates(tmp_path):
    path = str(tmp_path / "wallet.key")
    acct = load_or_create_account(path, BASE_SEPOLIA)
    assert acct is not None and os.path.exists(path)

@pytest.mark.parametrize("chain_id", sorted(MAINNET_CHAIN_IDS))
def test_mainnet_never_silently_creates_a_wallet(tmp_path, chain_id):
    path = str(tmp_path / "wallet.key")
    with pytest.raises(RuntimeError, match="refusing to silently create"):
        load_or_create_account(path, chain_id)
    assert not os.path.exists(path)

def test_mainnet_loads_an_existing_wallet_fine(tmp_path):
    path = str(tmp_path / "wallet.key")
    created = create_account(path)
    loaded = load_or_create_account(path, BASE_MAINNET)
    assert loaded.address == created.address


# ---- CLI: init ------------------------------------------------------------------

@pytest.fixture()
def in_tmp_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    return tmp_path

def test_init_creates_policy_and_wallet_and_prints_address(in_tmp_cwd, capsys):
    from imprest.cli import cmd_init

    cmd_init()
    out = capsys.readouterr().out
    assert os.path.exists("policy.yaml") and os.path.exists("wallet.key")
    assert load_account("wallet.key").address in out
    assert "never leaves this machine" in out

def test_init_is_idempotent_and_never_touches_existing_files(in_tmp_cwd, capsys):
    from imprest.cli import cmd_init

    cmd_init()
    address = load_account("wallet.key").address
    with open("policy.yaml", "a") as f:
        f.write("# operator edit\n")

    cmd_init()                                   # second run: keeps, re-prints
    out = capsys.readouterr().out
    assert load_account("wallet.key").address == address
    assert "already exists" in out and address in out
    with open("policy.yaml") as f:
        assert "# operator edit" in f.read()     # operator's edit survived


# ---- CLI: status ------------------------------------------------------------------

def test_status_without_wallet_says_how_to_get_one(in_tmp_cwd, capsys):
    from imprest.cli import cmd_status

    cmd_status()
    out = capsys.readouterr().out
    assert "imprest init" in out            # both wallet and policy lines
    assert "sends" in out

def test_status_reports_balances_via_chain(in_tmp_cwd, capsys, monkeypatch):
    from imprest import cli
    from imprest.cli import cmd_init, cmd_status
    from imprest.configs.base import settings

    cmd_init()
    capsys.readouterr()

    class FakeW3Eth:
        gas_price = 10**9
    class FakeW3:
        eth = FakeW3Eth()
        @staticmethod
        def to_wei(v, unit):
            return int(v * 10**18)
    class FakeChain:
        def __init__(self, *a, **kw):
            self.w3 = FakeW3()
        def get_balance(self, address):
            from decimal import Decimal
            return Decimal("0.002")
        def get_token_balance(self, token, address, decimals):
            from decimal import Decimal
            return Decimal("18.4")

    import imprest.services.chain as chain_mod
    monkeypatch.setattr(chain_mod, "Chain", FakeChain)
    monkeypatch.setattr(settings, "chain_id", 8453)   # network with a USDC entry

    cmd_status()
    out = capsys.readouterr().out
    assert "18.40 USDC" in out and "0.002000 ETH" in out
    assert "Base" in out and "sends" in out

def test_serve_is_the_default_and_subcommands_dispatch(monkeypatch):
    from imprest.cli import run_command

    assert run_command([]) is False              # no subcommand -> server path
    called = []
    monkeypatch.setattr("imprest.cli.cmd_status", lambda: called.append(1))
    assert run_command(["status"]) is True and called == [1]
