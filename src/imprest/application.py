"""Application factory — builds and wires the MCP server.

Mirrors the work backend's create_application(): compose the services, register
the transport layer, return the app. Nothing here implements business logic;
it only assembles the pieces.
"""

from __future__ import annotations

from imprest.api.payments import register_payment_tools
from imprest.configs.base import settings
from imprest.services.audit import AuditLog
from imprest.services.policy import PolicyStore


def create_application():
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("imprest")

    store = PolicyStore.load(settings.policy_path)
    audit = AuditLog(settings.audit_db_path)

    # Chain is built lazily: only construct web3/RPC when a tool actually needs it,
    # so a policy-only demo runs with no network configured.
    def get_chain():
        from decimal import Decimal

        from imprest.services.chain import Chain
        from imprest.services.wallet import load_or_create_account

        account = load_or_create_account(settings.keystore_path, settings.chain_id)
        return Chain(
            settings.rpc_url,
            settings.chain_id,
            account=account,
            max_fee_gwei=Decimal(str(settings.max_fee_gwei)),
            erc20_gas_limit=settings.erc20_gas_limit,
            receipt_timeout=settings.receipt_timeout,
        )

    register_payment_tools(
        mcp,
        store,
        audit,
        get_chain=get_chain,
        enable_sends=settings.enable_sends,
        chain_id=settings.chain_id,
    )
    return mcp
