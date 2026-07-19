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

from imprest.schemas.schemas import (
    AllowanceRecord,
    Decision,
    PaymentRequest,
    SpendRecord,
)
from imprest.services.audit import AuditLog
from imprest.services.auth import current_agent_id, current_is_admin
from imprest.services.chain import _to_base_units
from imprest.services.policy import PolicyEngine, PolicyStore
from imprest.services.tokens import token_for

# widest policy window is daily; only the last 24h can affect a decision.
_BUDGET_WINDOW = timedelta(hours=24)

# Every decision and every on-chain outcome is logged here (to stderr, so it
# never corrupts the stdio MCP protocol on stdout). This is the operational
# companion to the audit log: the audit table is the durable record, these logs
# are the live stream you tail while the server runs.
log = logging.getLogger("imprest.payments")


class X402SettlementUnknown(Exception):
    """Raised when an x402 signature was transmitted but the outcome is unknown.

    Distinct from a plain failure: the authorization may have settled on-chain,
    so the payment MUST count toward the budget and MUST NOT be retried into a
    second (differently-nonced) signature. See _execute_x402.
    """


def _now() -> datetime:
    return datetime.now(timezone.utc)


def register_payment_tools(
    mcp,
    store: PolicyStore,
    audit: AuditLog,
    get_chain=None,
    enable_sends: bool = False,
    chain_id: int = 0,
    x402_http=None,
    x402_resolve=None,
) -> None:
    """Attach the payment tools to an MCP server.

    `get_chain` is a zero-arg callable returning a Chain, invoked lazily so the
    server can run for policy demos without web3/an RPC configured. `chain_id`
    selects which token contracts a symbol like "USDC" resolves to (config, so
    token requests validate without a live chain connection). `x402_http` is an
    injectable httpx-compatible client for the x402 tool (tests pass a mock;
    None means construct a real one lazily).
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

    _http = {"client": x402_http}

    # Local http is allowed only against a testnet chain, never on mainnet —
    # a mainnet money-guard host has no business fetching localhost.
    _allow_local_http = chain_id in (84532, 11155111, 31337)

    def _x402_client():
        if _http["client"] is None:
            import httpx

            # follow_redirects=False is REQUIRED: x402svc.safe_get follows hops
            # manually so the SSRF guard runs on every Location, not just the
            # first URL. Timeout is short — this fetch runs under the agent lock.
            _http["client"] = httpx.Client(timeout=15, follow_redirects=False)
        return _http["client"]

    def _execute_x402(request: PaymentRequest, url: str, nonce: str) -> dict:
        """Complete an already-cleared x402 payment: handshake, sign, retry.

        Re-fetches the 402 requirements fresh (a signed authorization must
        match the CURRENT demand) and refuses if the terms drifted from what
        was cleared: different payee, different asset, or a higher price.

        Returns {"paid": True, ...} on a settled purchase, {"paid": False} if
        the resource became free (no payment made). Raises X402SettlementUnknown
        if the X-PAYMENT header was already transmitted when the failure hit —
        the signed authorization may have settled on-chain, so the caller must
        NOT treat that as a no-spend failure. Any pre-transmission failure
        raises a plain error (nothing was signed / sent).
        """
        import time

        from imprest.services import x402 as x402svc

        http = _x402_client()
        resp = x402svc.safe_get(http, url, allow_local=_allow_local_http,
                                resolve=x402_resolve)
        if 200 <= resp.status_code < 300:
            # Went free since we looked — the resource is ours, nothing to pay.
            return {"paid": False, "tx_hash": None, "status": resp.status_code,
                    "body": resp.text[:2000], "note": "no payment required"}
        if resp.status_code != 402:
            raise RuntimeError(f"expected 402 or 2xx from {url}, "
                               f"got HTTP {resp.status_code}")
        offer = x402svc.parse_402(resp.json(), chain_id)
        if offer.pay_to.lower() != request.recipient.lower():
            raise RuntimeError("payment terms changed: payee differs from the "
                               "one the policy cleared")
        if offer.asset_symbol != request.asset:
            raise RuntimeError("payment terms changed: asset differs from the "
                               "one the policy cleared")
        if offer.amount > request.amount:
            raise RuntimeError(f"payment terms changed: price rose to "
                               f"{offer.amount} {offer.asset_symbol}, above the "
                               f"cleared {request.amount}")

        account = get_chain().account
        header = x402svc.sign_payment_header(account, offer, chain_id,
                                             int(time.time()), nonce)
        # From here on the authorization is in the server's hands and may settle
        # on-chain regardless of the HTTP outcome — failures become "unknown".
        try:
            paid = x402svc.safe_get(http, url, headers={"X-PAYMENT": header},
                                    allow_local=_allow_local_http,
                                    resolve=x402_resolve)
        except Exception as e:  # noqa: BLE001 - network blip AFTER handing over the sig
            raise X402SettlementUnknown(
                f"payment sent but response failed ({e}); settlement unknown"
            ) from e
        if not (200 <= paid.status_code < 300):
            raise X402SettlementUnknown(
                f"payment sent but not accepted: HTTP {paid.status_code} "
                f"{paid.text[:200]}; settlement unknown"
            )
        settle = x402svc.decode_settlement(paid.headers.get("x-payment-response"))
        return {"paid": True,
                "tx_hash": settle.get("transaction") or "x402-settled",
                "status": paid.status_code, "body": paid.text[:2000],
                "settlement": settle}

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

    def _pay_x402(url: str, max_amount, reason: str) -> dict:
        """The x402 pipeline: probe, parse the demand, evaluate, sign, retry.

        Mirrors _process — same lock, same record-before-act, same verdicts —
        but the 'recipient' comes from the SERVER's 402 response, and execution
        is an EIP-3009 signature + HTTP retry instead of a broadcast.
        """
        from imprest.services import x402 as x402svc

        agent_id = current_agent_id.get()
        now = _now()

        try:
            cap = Decimal(str(max_amount))
            if not cap.is_finite() or cap <= 0:
                raise InvalidOperation
        except (InvalidOperation, ValueError):
            return {"error": "max_amount must be a positive finite number"}

        # 1. Probe (SSRF-vetted on every hop, size-capped). A non-402 answer
        #    means there is nothing to pay for.
        try:
            resp = x402svc.safe_get(_x402_client(), url,
                                    allow_local=_allow_local_http,
                                    resolve=x402_resolve)
        except x402svc.X402Unsafe as e:
            return {"error": f"refused: {e}"}
        except Exception as e:  # noqa: BLE001 - network errors go to the agent
            return {"error": f"fetch failed: {e}"}
        if resp.status_code != 402:
            return {"paid": False, "status": resp.status_code,
                    "body": resp.text[:2000]}

        # 2. Parse the payment demand; refuse anything off our chain/registry.
        try:
            offer = x402svc.parse_402(resp.json(), chain_id)
        except Exception as e:  # noqa: BLE001 - malformed 402s are denials
            return _reject(audit, agent_id, url, 0, reason, now, "N/A", "x402",
                           f"unpayable 402 from {url}: {e}", "x402_unpayable")

        # 3. The agent stated what it expected to pay; hold the server to it.
        #    (Policy caps bound the damage, but a $4.99 demand for a $0.01
        #    quote should die here, not sail through under the per-tx cap.)
        if offer.amount > cap:
            return _reject(audit, agent_id, offer.pay_to, str(offer.amount),
                           reason, now, offer.asset_symbol, "x402",
                           f"server demands {offer.amount} {offer.asset_symbol}, "
                           f"above the agent's stated max {cap}",
                           "x402_price_above_max")

        request = PaymentRequest(agent_id=agent_id, recipient=offer.pay_to,
                                 amount=offer.amount,
                                 reason=reason or f"x402: {url}",
                                 asset=offer.asset_symbol, operation="x402")

        # 4. The identical guarded pipeline: lock, history, evaluate, record.
        with _locks[agent_id]:
            history = [
                SpendRecord(recipient=r, amount=a, timestamp=t, asset=ast)
                for (r, a, t, ast) in audit.approved_spends(
                    agent_id, since=now - _BUDGET_WINDOW
                )
            ]
            engine = PolicyEngine(store.for_agent(agent_id))
            decision = engine.evaluate(request, history, now)
            row_id = audit.record(request, decision, now, context=url)

            tx_hash = None
            executed = False
            error = None
            result: dict = {}
            if decision.decision is Decision.ALLOW and enable_sends and get_chain:
                # Deterministic nonce keyed to THIS row: a retry re-sends the
                # same authorization, so a duplicate can never settle twice.
                nonce = x402svc.payment_nonce(f"{agent_id}:{row_id}")
                try:
                    result = _execute_x402(request, url, nonce)
                    if result.get("paid"):
                        tx_hash = result.get("tx_hash")
                        executed = True
                        audit.mark_executed(row_id, tx_hash)
                    else:
                        # Resource served free between probe and execute — no
                        # payment made, so this must NOT consume budget.
                        audit.mark_skipped(row_id, result.get("note") or "no payment")
                except X402SettlementUnknown as e:
                    # Signature was handed over; funds MAY have moved. Record a
                    # budget-consuming, non-retryable outcome — never "failed".
                    error = str(e)
                    audit.mark_settlement_unknown(row_id, error)
                except Exception as e:  # noqa: BLE001 - pre-send failure: no spend
                    error = str(e)
                    audit.mark_failed(row_id, error)

        log.info(
            "x402 agent=%s url=%s asset=%s amount=%s -> %s (%s) executed=%s tx=%s",
            agent_id, url, offer.asset_symbol, offer.amount,
            decision.decision.value, decision.rule, executed, tx_hash,
        )
        if error:
            log.warning("x402 agent=%s payment failed: %s", agent_id, error)

        out = {
            "decision": decision.decision.value,
            "allowed": decision.allowed,
            "rule": decision.rule,
            "detail": decision.reason,
            "asset": offer.asset_symbol,
            "operation": "x402",
            "price": str(offer.amount),
            "pay_to": offer.pay_to,
            "url": url,
            "executed": executed,
            "tx_hash": tx_hash,
            "error": error,
        }
        if result:
            out["status"] = result.get("status")
            out["body"] = result.get("body")
            out["paid"] = result.get("paid", False)
        if decision.decision is Decision.NEEDS_APPROVAL:
            out["payment_id"] = row_id
        return out

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

        imprest approves an EXACT amount only — never an unlimited allowance,
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
    def pay_x402(url: str, max_amount: float, reason: str = "") -> dict:
        """Fetch a paid HTTP resource, paying for it over the x402 protocol
        ("402 Payment Required"). Use this for pay-per-request APIs that quote
        a price in the 402 response; the spend policy decides whether the
        quoted price is allowed, blocked, or requires human approval.

        The payment is a signed one-time authorization for EXACTLY the quoted
        amount — never more — and it only happens if the quote passes policy.

        Args:
            url: the resource to fetch (https)
            max_amount: the most you expect this to cost, in whole token units
                        (e.g. 0.01 for 1 cent of USDC). If the server demands
                        more, the request is refused before policy even runs.
            reason: what the purchase is for (recorded in the audit log)
        """
        return _pay_x402(url, max_amount, reason)

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
            settlement_unknown = False
            x402_result: dict = {}
            if enable_sends and get_chain:
                try:
                    if request.operation == "x402":
                        from imprest.services import x402 as x402svc

                        # Deterministic nonce keyed to this row: re-resolving
                        # after a settlement-unknown re-sends the SAME auth.
                        nonce = x402svc.payment_nonce(f"{agent_id}:{payment_id}")
                        # The pending row remembers the URL; redo the handshake
                        # (fresh quote, checked against the approved terms).
                        x402_result = _execute_x402(
                            request, pending.get("context") or "", nonce
                        )
                        if x402_result.get("paid"):
                            tx_hash = x402_result.get("tx_hash")
                            executed = True
                            audit.mark_executed(payment_id, tx_hash)
                        else:
                            # Went free before we paid — no spend; close it out.
                            audit.mark_skipped(payment_id,
                                               x402_result.get("note") or "no payment")
                    else:
                        tx_hash = _execute_onchain(request)
                        executed = True
                        audit.mark_executed(payment_id, tx_hash)
                except X402SettlementUnknown as e:
                    # Signature already handed over: DO NOT revert to pending
                    # (a re-resolve is fine — same nonce — but the row must
                    # count toward the budget, so it is terminal here).
                    error = str(e)
                    settlement_unknown = True
                    audit.mark_settlement_unknown(payment_id, error)
                except Exception as e:  # noqa: BLE001 - pre-send failure: no spend
                    error = str(e)
                    # Don't burn the operator's decision on a transient failure:
                    # roll back to pending so it can be re-resolved.
                    audit.revert_to_pending(payment_id, error)

        if error and not settlement_unknown:
            log.warning("approval id=%s send failed, back to pending: %s",
                        payment_id, error)
            return {"resolved": False, "executed": False,
                    "decision": "needs_approval",
                    "detail": f"send failed, still pending: {error}",
                    "error": error, "payment_id": payment_id}
        if settlement_unknown:
            log.warning("approval id=%s settlement unknown (counted): %s",
                        payment_id, error)
            return {"resolved": True, "executed": False,
                    "decision": "settlement_unknown",
                    "detail": error, "error": error, "payment_id": payment_id}

        log.info("approval id=%s approved by=%s agent=%s executed=%s tx=%s",
                 payment_id, approver, agent_id, executed, tx_hash)
        out = {"resolved": True, "executed": executed, "decision": "allow",
               "asset": request.asset, "operation": request.operation,
               "tx_hash": tx_hash, "error": error, "payment_id": payment_id}
        if x402_result:
            out["status"] = x402_result.get("status")
            out["body"] = x402_result.get("body")
        return out

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
    from imprest.schemas.schemas import PolicyDecision

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
