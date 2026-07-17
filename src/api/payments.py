"""MCP tools — the server's public surface (the transport layer).

These are what an agent (or Claude Desktop, Cursor, anyone) sees. Each tool is
thin: it gathers inputs, delegates to the services (policy / audit / chain), and
returns a plain dict. All the money-guarding logic lives in the policy engine,
NOT here.

The star is `request_payment`: it runs the policy check, records the attempt,
and only executes the transfer if the policy said ALLOW *and* sends are enabled.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal

from src.schemas.schemas import Decision, PaymentRequest
from src.services.audit import AuditLog
from src.services.policy import PolicyEngine


def _now() -> datetime:
    return datetime.now(timezone.utc)


def register_payment_tools(
    mcp,
    engine: PolicyEngine,
    audit: AuditLog,
    get_chain=None,
    enable_sends: bool = False,
) -> None:
    """Attach the payment tools to an MCP server.

    `get_chain` is a zero-arg callable returning a Chain, invoked lazily so the
    server can run for policy demos without web3/an RPC configured.
    """

    @mcp.tool()
    def request_payment(recipient: str, amount: float, reason: str = "") -> dict:
        """Request to pay some ETH to an address. The spend policy decides whether
        it is allowed, blocked, or requires human approval. Use this whenever you
        need to send a payment; do not attempt to move funds any other way.

        Args:
            recipient: destination 0x address
            amount: amount of ETH to send
            reason: what the payment is for (recorded in the audit log)
        """
        request = PaymentRequest(
            agent_id="demo-agent",
            recipient=recipient,
            amount=Decimal(str(amount)),
            reason=reason,
        )
        now = _now()

        # 1. Reconstruct spend history from the audit log and ask the policy.
        history = [
            _spend_record(r, a, t)
            for (r, a, t) in audit.approved_spends(request.agent_id)
        ]
        decision = engine.evaluate(request, history, now)

        # 2. Execute only if allowed outright AND sends are enabled.
        tx_hash = None
        executed = False
        if decision.decision is Decision.ALLOW and enable_sends and get_chain:
            tx_hash = get_chain().send_eth(request.recipient, request.amount)
            executed = True

        # 3. Always record the attempt.
        audit.record(request, decision, now, tx_hash=tx_hash)

        return {
            "decision": decision.decision.value,
            "allowed": decision.allowed,
            "rule": decision.rule,
            "detail": decision.reason,
            "executed": executed,
            "tx_hash": tx_hash,
        }

    @mcp.tool()
    def get_balance(address: str) -> dict:
        """Get the ETH balance of an address (read-only)."""
        if not get_chain:
            return {"error": "chain not configured"}
        return {"address": address, "balance_eth": str(get_chain().get_balance(address))}

    @mcp.tool()
    def get_gas_price() -> dict:
        """Get the current gas price in gwei (read-only)."""
        if not get_chain:
            return {"error": "chain not configured"}
        return {"gas_price_gwei": str(get_chain().gas_price_gwei())}

    @mcp.tool()
    def get_audit_log() -> dict:
        """Return the full history of this agent's payment attempts and what the
        policy decided about each — approved, denied, or executed."""
        return {"entries": audit.history("demo-agent")}


def _spend_record(recipient: str, amount: Decimal, ts: datetime):
    from src.schemas.schemas import SpendRecord

    return SpendRecord(recipient=recipient, amount=amount, timestamp=ts)
