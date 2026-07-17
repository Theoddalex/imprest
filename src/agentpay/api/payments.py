"""MCP tools — the server's public surface (the transport layer).

These are what an agent (or Claude Desktop, Cursor, anyone) sees. Each tool is
thin: it gathers inputs, delegates to the services (policy / audit / chain), and
returns a plain dict. All the money-guarding logic lives in the policy engine,
NOT here.

The star is `request_payment`. Its critical section — read history, evaluate,
record, send — runs under a per-agent lock so two concurrent requests can't both
pass the same budget check (check-then-act must be atomic). The attempt is
recorded BEFORE the send, then stamped executed/failed, so money can never move
without a corresponding audit row.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from agentpay.schemas.schemas import (
    AllowanceRecord,
    Decision,
    PaymentRequest,
    SpendRecord,
)
from agentpay.services.audit import AuditLog
from agentpay.services.auth import current_agent_id, current_is_admin
from agentpay.services.chain import _to_base_units
from agentpay.services.policy import PolicyEngine, PolicyStore
from agentpay.services.tokens import token_for

# widest policy window is daily; only the last 24h can affect a decision.
_BUDGET_WINDOW = timedelta(hours=24)

# Every decision and every on-chain outcome is logged here (to stderr, so it
# never corrupts the stdio MCP protocol on stdout). This is the operational
# companion to the audit log: the audit table is the durable record, these logs
# are the live stream you tail while the server runs.
log = logging.getLogger("agentpay.payments")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def register_payment_tools(
    mcp,
    store: PolicyStore,
    audit: AuditLog,
    get_chain=None,
    enable_sends: bool = False,
    chain_id: int = 0,
) -> None:
    """Attach the payment tools to an MCP server.

    `get_chain` is a zero-arg callable returning a Chain, invoked lazily so the
    server can run for policy demos without web3/an RPC configured. `chain_id`
    selects which token contracts a symbol like "USDC" resolves to (config, so
    token requests validate without a live chain connection).
    """

    # One lock per agent: serialises each agent's read-check-record-send cycle
    # without blocking unrelated agents. (Single-process assumption — see README;
    # multi-worker deployments need a DB-level lock, not yet supported.)
    _locks: dict[str, threading.Lock] = defaultdict(threading.Lock)

    def _execute_onchain(request: PaymentRequest) -> str:
        """Perform the actual chain call for an already-ALLOW'd request.

        The single place any funds move or any allowance is granted. Returns the
        tx hash; raises on RPC/broadcast failure (the caller records that).
        """
        chain = get_chain()
        if request.asset == "ETH":
            return chain.send_eth(request.recipient, request.amount)
        token = token_for(chain_id, request.asset)
        if request.operation == "approve":
            return chain.approve_erc20(
                token.address, request.recipient, request.amount, token.decimals
            )
        return chain.send_erc20(
            token.address, request.recipient, request.amount, token.decimals
        )

    def _live_allowances(agent_id: str) -> list[AllowanceRecord]:
        """The agent's live token allowances (the standing-liability ledger)."""
        return [
            AllowanceRecord(spender=s, amount=a, asset=ast)
            for (s, a, ast) in audit.outstanding_allowances(agent_id)
        ]

    def _process(operation: str, recipient: str, amount, reason: str, asset: str) -> dict:
        """The shared money path for both transfers and approvals.

        Both operations run the identical guardrail pipeline — validate, take the
        per-agent lock, load history, evaluate policy, record BEFORE acting, then
        execute on ALLOW — differing only in the chain call at the end. An
        approval is treated like a spend for policy purposes: a granted allowance
        is committed value, so it is capped by the same per-transaction limit and
        counts against the same budget (this is what closes the "many small
        approvals" drain).
        """
        # Identity comes from authentication (Bearer key over HTTP, or the
        # configured local identity over stdio) — never from the agent's input,
        # which could simply lie about who it is.
        agent_id = current_agent_id.get()
        now = _now()
        asset = asset.upper()

        # Validate the amount at the boundary: reject NaN/Infinity before it can
        # reach (and crash) the policy engine's comparisons.
        try:
            amt = Decimal(str(amount))
            if not amt.is_finite():
                raise InvalidOperation
        except (InvalidOperation, ValueError):
            return _reject(audit, agent_id, recipient, amount, reason, now, asset,
                           operation, "amount must be a finite number", "amount_finite")

        request = PaymentRequest(agent_id=agent_id, recipient=recipient, amount=amt,
                                 reason=reason, asset=asset, operation=operation)

        # Validate the recipient/spender format before we ever return ALLOW.
        if not _looks_like_address(recipient):
            return _reject(audit, agent_id, recipient, amount, reason, now, asset,
                           operation,
                           f"recipient {recipient!r} is not a valid address",
                           "recipient_format")

        # A non-native asset must resolve to a token we actually know how to move
        # on this network. This is a config guard distinct from the policy's
        # token allowlist: policy may permit "USDC" but the contract for it must
        # also be known here, or we could never execute an ALLOW.
        token = None
        if asset != "ETH":
            token = token_for(chain_id, asset)
            if token is None:
                return _reject(audit, agent_id, recipient, amount, reason, now, asset,
                               operation,
                               f"asset {asset} is not a known token on this network",
                               "asset_unknown")
            # Reject sub-token-precision amounts at the boundary, not at broadcast:
            # a recorded ALLOW must always be executable (else it fails only when
            # an operator has already approved it — see _to_base_units).
            try:
                _to_base_units(amt, token.decimals)
            except ValueError:
                return _reject(audit, agent_id, recipient, amount, reason, now, asset,
                               operation,
                               f"amount {amt} exceeds {asset}'s {token.decimals} decimals",
                               "amount_precision")
        elif operation == "approve":
            # Native ETH has no allowance concept — approve() is ERC-20 only.
            return _reject(audit, agent_id, recipient, amount, reason, now, asset,
                           operation, "ETH has no allowance to approve",
                           "approve_requires_token")

        with _locks[agent_id]:
            # 1. THIS agent's recent spends (bounded to the budget window) + policy.
            history = [
                SpendRecord(recipient=r, amount=a, timestamp=t, asset=ast)
                for (r, a, t, ast) in audit.approved_spends(
                    agent_id, since=now - _BUDGET_WINDOW
                )
            ]
            # An approve is judged against the allowance ledger too: the total
            # of LIVE allowances (which outlive budget windows) stays capped.
            allowances = _live_allowances(agent_id) if operation == "approve" else []
            engine = PolicyEngine(store.for_agent(agent_id))
            decision = engine.evaluate(request, history, now, allowances)

            # 2. Record the attempt BEFORE any send, so nothing goes unlogged.
            row_id = audit.record(request, decision, now)

            # 3. Execute only on outright ALLOW with sends enabled.
            tx_hash = None
            executed = False
            error = None
            if decision.decision is Decision.ALLOW and enable_sends and get_chain:
                try:
                    tx_hash = _execute_onchain(request)
                    executed = True
                    audit.mark_executed(row_id, tx_hash)
                except Exception as e:  # noqa: BLE001 - record every outcome
                    error = str(e)
                    audit.mark_failed(row_id, error)

        log.info(
            "%s agent=%s asset=%s amount=%s -> %s (%s) executed=%s tx=%s",
            operation, agent_id, asset, amt, decision.decision.value,
            decision.rule, executed, tx_hash,
        )
        if error:
            log.warning("%s agent=%s send failed: %s", operation, agent_id, error)

        return {
            "decision": decision.decision.value,
            "allowed": decision.allowed,
            "rule": decision.rule,
            "detail": decision.reason,
            "asset": asset,
            "operation": operation,
            "executed": executed,
            "tx_hash": tx_hash,
            "error": error,
        }

    @mcp.tool()
    def request_payment(
        recipient: str, amount: float, reason: str = "", asset: str = "ETH"
    ) -> dict:
        """Request to pay an address. The spend policy decides whether it is
        allowed, blocked, or requires human approval. Use this whenever you need
        to send a payment; do not attempt to move funds any other way.

        Args:
            recipient: destination 0x address
            amount: amount to send, in whole units of `asset` (e.g. 0.05, 50)
            reason: what the payment is for (recorded in the audit log)
            asset: what to send — "ETH" (native, the default) or a token symbol
                   such as "USDC". Each asset has its own policy limits.
        """
        return _process("transfer", recipient, amount, reason, asset)

    @mcp.tool()
    def request_approval(
        spender: str, amount: float, asset: str, reason: str = ""
    ) -> dict:
        """Grant a token spender an allowance so a contract (a marketplace,
        subscription, or swap) can later pull funds. The policy decides whether
        it is allowed, blocked, or needs human approval.

        agentpay approves an EXACT amount only — never an unlimited allowance,
        the vector behind most token drains. The allowance is capped by, and
        counts against, the same per-asset limits as a direct payment, and the
        TOTAL of live allowances across all spenders is itself capped (an
        allowance outlives budget windows, so it is tracked as a standing
        liability). Approving 0 revokes the spender's allowance and frees cap.

        Args:
            spender: the 0x address being granted the allowance
            amount: the allowance, in whole units of `asset` (e.g. 25 for
                    25 USDC); 0 revokes this spender's existing allowance
            asset: the token symbol (e.g. "USDC"); native ETH cannot be approved
            reason: what the approval is for (recorded in the audit log)
        """
        return _process("approve", spender, amount, reason, asset)

    @mcp.tool()
    def list_pending_approvals() -> dict:
        """(operator only) List payments/approvals waiting for a human decision.

        Requires an admin identity — an agent cannot see or clear its own
        pending approvals. Over stdio the local operator is the admin.
        """
        if not current_is_admin.get():
            return {"error": "admin only: this requires an operator identity"}
        return {"pending": audit.pending_approvals()}

    @mcp.tool()
    def resolve_approval(payment_id: int, approve: bool = True, note: str = "") -> dict:
        """(operator only) Approve or reject a pending payment and, on approval,
        execute it. This is the resume path for `needs_approval`.

        A human approval overrides only the approval threshold — the hard limits
        (per-transaction cap, budgets, deny/allow list) are RE-CHECKED against
        the current ledger at approval time, so an approval that would now bust a
        budget is refused rather than forced through.

        Args:
            payment_id: the audit id of the pending row (from list_pending_approvals)
            approve: True to approve and execute, False to reject
            note: optional operator note recorded on the row
        """
        if not current_is_admin.get():
            return {"error": "admin only: approvals require an operator identity"}
        approver = current_agent_id.get()
        now = _now()

        pending = audit.get_pending(payment_id)
        if pending is None:
            return {"error": f"no pending approval with id {payment_id}"}

        agent_id = pending["agent_id"]
        request = PaymentRequest(
            agent_id=agent_id, recipient=pending["recipient"],
            amount=Decimal(pending["amount"]), reason=pending["reason"] or "",
            asset=pending["asset"], operation=pending["operation"],
        )

        # Serialise against that agent's own request pipeline: the budget re-check
        # and the execute must be atomic w.r.t. concurrent spends by the agent.
        with _locks[agent_id]:
            # Guard the race where another admin resolved it first.
            if audit.get_pending(payment_id) is None:
                return {"error": f"approval {payment_id} is no longer pending"}

            if not approve:
                audit.mark_rejected(payment_id, approver, note or "rejected by operator")
                log.info("approval id=%s rejected by=%s agent=%s",
                         payment_id, approver, agent_id)
                return {"resolved": True, "executed": False, "decision": "rejected",
                        "payment_id": payment_id}

            # Re-evaluate hard limits against the CURRENT ledger.
            history = [
                SpendRecord(recipient=r, amount=a, timestamp=t, asset=ast)
                for (r, a, t, ast) in audit.approved_spends(
                    agent_id, since=now - _BUDGET_WINDOW
                )
            ]
            allowances = (
                _live_allowances(agent_id)
                if request.operation == "approve" else []
            )
            recheck = PolicyEngine(store.for_agent(agent_id)).evaluate(
                request, history, now, allowances
            )
            if recheck.decision is Decision.DENY:
                # A hard limit now blocks it; the human ok cannot override that.
                audit.mark_rejected(payment_id, approver,
                                    f"blocked at approval: {recheck.reason}")
                log.warning("approval id=%s by=%s blocked at approval: %s (%s)",
                            payment_id, approver, recheck.rule, recheck.reason)
                return {"resolved": True, "executed": False, "decision": "deny",
                        "rule": recheck.rule, "detail": recheck.reason,
                        "payment_id": payment_id}

            # Human override applies: needs_approval -> allow (now counts to budget).
            audit.mark_approved(payment_id, approver)

            tx_hash = None
            executed = False
            error = None
            if enable_sends and get_chain:
                try:
                    tx_hash = _execute_onchain(request)
                    executed = True
                    audit.mark_executed(payment_id, tx_hash)
                except Exception as e:  # noqa: BLE001 - record every outcome
                    error = str(e)
                    # Don't burn the operator's decision on a transient failure:
                    # roll back to pending so it can be re-resolved.
                    audit.revert_to_pending(payment_id, error)

        if error:
            log.warning("approval id=%s send failed, back to pending: %s",
                        payment_id, error)
            return {"resolved": False, "executed": False,
                    "decision": "needs_approval",
                    "detail": f"send failed, still pending: {error}",
                    "error": error, "payment_id": payment_id}

        log.info("approval id=%s approved by=%s agent=%s executed=%s tx=%s",
                 payment_id, approver, agent_id, executed, tx_hash)
        return {"resolved": True, "executed": executed, "decision": "allow",
                "asset": request.asset, "operation": request.operation,
                "tx_hash": tx_hash, "error": error, "payment_id": payment_id}

    @mcp.tool()
    def get_balance(address: str, asset: str = "ETH") -> dict:
        """Get the balance of an address (read-only).

        Args:
            address: the 0x address to check
            asset: "ETH" (native, default) or a token symbol such as "USDC"
        """
        if not get_chain:
            return {"error": "chain not configured"}
        asset = asset.upper()
        if asset == "ETH":
            balance = get_chain().get_balance(address)
        else:
            token = token_for(chain_id, asset)
            if token is None:
                return {"error": f"asset {asset} is not a known token on this network"}
            balance = get_chain().get_token_balance(token.address, address, token.decimals)
        return {"address": address, "asset": asset, "balance": str(balance)}

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
        return {"entries": audit.history(current_agent_id.get())}


def _looks_like_address(addr: str) -> bool:
    """Cheap 0x + 40-hex check (avoids importing web3 for validation)."""
    if not isinstance(addr, str) or not addr.startswith("0x") or len(addr) != 42:
        return False
    try:
        int(addr, 16)
        return True
    except ValueError:
        return False


def _reject(audit, agent_id, recipient, amount, reason, now, asset, operation,
            detail, rule) -> dict:
    """Record a boundary-level denial and return the standard response shape."""
    from agentpay.schemas.schemas import PolicyDecision

    decision = PolicyDecision(Decision.DENY, detail, rule)
    request = PaymentRequest(
        agent_id=agent_id,
        recipient=str(recipient),
        amount=Decimal(0),
        reason=reason,
        asset=asset,
        operation=operation,
    )
    audit.record(request, decision, now)
    return {
        "decision": "deny", "allowed": False, "rule": rule, "detail": detail,
        "asset": asset, "operation": operation, "executed": False,
        "tx_hash": None, "error": None,
    }
