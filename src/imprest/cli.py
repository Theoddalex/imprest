"""Operator CLI — `imprest init` and `imprest status`.

init   is the onboarding ceremony: create policy.yaml (the limits) and the
       agent's dedicated wallet (the prepaid card), then print the funding
       address. Key generation is explicit and announced — never a silent
       side effect of a payment.
status is the card-check: address, balances, roughly how much gas is left,
       the active policy limits, and whether sends are enabled.

Both write to stdout: they run as CLI commands, never under the stdio MCP
transport (main.py routes subcommands before any server starts).
"""

from __future__ import annotations

import getpass
import os
import sys
from decimal import Decimal

NETWORKS = {
    1: "Ethereum",
    8453: "Base",
    84532: "Base Sepolia",
    11155111: "Ethereum Sepolia",
}

POLICY_TEMPLATE = """\
# imprest spend policy — the guardrails your agent CANNOT override.
#
# STABLECOIN-FIRST: agents pay vendors in tokens (USDC). ETH in this wallet
# is gas money only, so its limits are near zero — any real ETH payment
# attempt should look anomalous and get denied/escalated.
#
# A token is payable ONLY if it has an `assets` entry — the map doubles as
# the token allowlist. Amounts are whole units (10 = 10 USDC).

default:
  # --- ETH: gas-only lane ---
  per_transaction_max: 0.002
  hourly_max: 0.003
  daily_max: 0.005
  approval_threshold: 0.001
  rate_limit_per_minute: 5
  allowlist: []          # if non-empty, ONLY these recipients (lowercase)
  denylist: []           # never pay these, overrides everything
  # What an allowlist miss means. "deny" blocks outright; "ask" sends the
  # payment to the approval queue instead (all other limits still apply),
  # so your agent can propose NEW vendors and you rule per payment.
  unknown_recipient: deny
  # --- Stablecoins: the real spending lanes ---
  assets:
    USDC:
      per_transaction_max: 10
      hourly_max: 20
      daily_max: 50
      approval_threshold: 5          # above this, a human must approve
      max_outstanding_allowance: 20  # cap on TOTAL live approve() allowances

# Per-agent overrides (identity = API key over HTTP, AGENT_ID over stdio):
# agents:
#   support-bot:
#     assets:
#       USDC: {per_transaction_max: 2, hourly_max: 5, daily_max: 10,
#              approval_threshold: 1, max_outstanding_allowance: 5}
"""


def _network(chain_id: int) -> str:
    return NETWORKS.get(chain_id, f"chain {chain_id}")


def cmd_init(import_key: bool = False) -> None:
    from imprest.configs.base import settings
    from imprest.services.wallet import (
        MAINNET_CHAIN_IDS,
        create_account,
        load_account,
    )

    net = _network(settings.chain_id)
    mainnet = settings.chain_id in MAINNET_CHAIN_IDS

    # 1. Policy first — limits should exist before the wallet they guard.
    if os.path.exists(settings.policy_path):
        print(f"  · {settings.policy_path} already exists (kept)")
    else:
        with open(settings.policy_path, "w") as f:
            f.write(POLICY_TEMPLATE)
        print(f"  ✓ created {settings.policy_path}   (edit this — these are your agent's limits)")

    # 2. Wallet — create, import, or report the existing one.
    if os.path.exists(settings.keystore_path):
        acct = load_account(settings.keystore_path)
        print(f"  · {settings.keystore_path} already exists (kept) — never overwritten")
    else:
        key = None
        if import_key:
            key = getpass.getpass("  private key to import (hex, not echoed): ").strip()
            print("  ! importing an existing key — the recommended model is a fresh,")
            print("    dedicated wallet funded with only what the agent may spend")
        acct = create_account(settings.keystore_path, private_key=key or None)
        origin = "imported into" if key else "generated locally in"
        print(f"  ✓ {origin} {settings.keystore_path} — the key never leaves this machine")

    # 3. The part the operator actually needs: where to send funds.
    print()
    print(f"  agent wallet   {acct.address}")
    print(f"  network        {net}")
    print()
    if mainnet:
        print("  This wallet is a prepaid card: fund it with only what your agent")
        print("  may spend. Send USDC plus a little ETH (for gas) to the address")
        print(f"  above — and withdraw on the {net.upper()} network, not another chain.")
    else:
        print(f"  {net} is a testnet — fund the address with faucet play money")
        print("  (e.g. Circle's USDC faucet) to try everything risk-free.")
    print()
    state = "ENABLED — the agent can move funds" if settings.enable_sends \
        else "OFF (ENABLE_SENDS=false) — flip it only when you're ready"
    print(f"  sends          {state}")


def cmd_status() -> None:
    from imprest.configs.base import settings
    from imprest.services.policy import PolicyStore
    from imprest.services.tokens import token_for
    from imprest.services.wallet import load_account

    net = _network(settings.chain_id)

    # Wallet
    try:
        acct = load_account(settings.keystore_path)
    except FileNotFoundError as e:
        print(f"  wallet   {e}")
        acct = None

    if acct:
        print(f"  wallet   {acct.address}")
        try:
            from imprest.services.chain import Chain

            chain = Chain(settings.rpc_url, settings.chain_id)
            eth = chain.get_balance(acct.address)
            line = f"{eth:.6f} ETH"
            token = token_for(settings.chain_id, "USDC")
            if token:
                usdc = chain.get_token_balance(token.address, acct.address, token.decimals)
                line = f"{usdc:.2f} USDC · {line}"
            gas_price = chain.w3.eth.gas_price
            per_tx = max(gas_price, 1) * settings.erc20_gas_limit
            txs = int(chain.w3.to_wei(eth, "ether") // per_tx)
            print(f"  balance  {line} (gas ≈ {txs} token transfers)")
        except Exception as e:  # noqa: BLE001 - status must degrade, not crash
            print(f"  balance  unavailable ({e})")

    # Policy (for the identity this process would run as)
    try:
        policy = PolicyStore.load(settings.policy_path).for_agent(settings.agent_id)
        usdc = policy.limits_for("USDC")
        if usdc:
            print(f"  policy   USDC per-tx {usdc.per_transaction_max} · "
                  f"daily {usdc.daily_max} · approval >{usdc.approval_threshold} · "
                  f"allowance cap {usdc.outstanding_allowance_cap}")
        print(f"           ETH per-tx {policy.per_transaction_max} (gas-only lane) · "
              f"identity '{settings.agent_id}'")
    except FileNotFoundError:
        print(f"  policy   no {settings.policy_path} — run `imprest init`")

    print(f"  network  {net} (chain {settings.chain_id})")
    print(f"  sends    {'ENABLED' if settings.enable_sends else 'OFF (ENABLE_SENDS=false)'}")


def run_command(argv: list[str]) -> bool:
    """Dispatch `init`/`status`; False means: no subcommand, run the server."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="imprest",
        description="Spend-control MCP server between AI agents and a wallet. "
                    "With no subcommand, runs the server (transport from .env).",
    )
    sub = parser.add_subparsers(dest="command")
    p_init = sub.add_parser("init", help="create policy.yaml + the agent's wallet, print the funding address")
    p_init.add_argument("--import-key", action="store_true",
                        help="import an existing private key instead of generating one")
    sub.add_parser("status", help="wallet address, balances, policy limits, sends switch")
    sub.add_parser("serve", help="run the MCP server (the default)")

    args = parser.parse_args(argv)
    if args.command == "init":
        cmd_init(import_key=args.import_key)
        return True
    if args.command == "status":
        cmd_status()
        return True
    return False


if __name__ == "__main__":
    run_command(sys.argv[1:])
