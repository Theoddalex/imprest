"""Application factory — builds and wires the MCP server.

Mirrors the work backend's create_application(): compose the services, register
the transport layer, return the app. Nothing here implements business logic;
it only assembles the pieces.
"""

from __future__ import annotations

from agentpay.api.payments import register_payment_tools
from agentpay.configs.base import settings
from agentpay.services.audit import AuditLog
from agentpay.services.policy import PolicyEngine, load_policy


def create_application():
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("agentpay")

    engine = PolicyEngine(load_policy(settings.policy_path))
    audit = AuditLog(settings.audit_db_path)

    # Chain is built lazily: only construct web3/RPC when a tool actually needs it,
    # so a policy-only demo runs with no network configured.
    def get_chain():
        from agentpay.services.chain import Chain
        from agentpay.services.wallet import load_or_create_account

        account = load_or_create_account(settings.keystore_path)
        return Chain(settings.rpc_url, settings.chain_id, account=account)

    register_payment_tools(
        mcp,
        engine,
        audit,
        get_chain=get_chain,
        enable_sends=settings.enable_sends,
    )
    return mcp
