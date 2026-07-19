"""Append-only audit log.

Every payment attempt — approved, denied, or executed — is recorded. For a
spend-control product this log IS half the value: "show me everything my agent
tried to spend, and what your policy did about it."

SQLite because it's zero-setup and easy to query. Rows are INSERTed; the only
UPDATE is stamping a pending payment with its on-chain outcome (tx hash or
failure), which is why each row carries a `status`:

    recorded  - policy decision made, no send attempted
                (covers deny, needs_approval, and allow-with-sends-off)
    executed  - the transfer was broadcast; tx_hash is set
    failed    - the transfer was attempted and raised BEFORE any funds could
                move; no funds moved (true for on-chain sends, and for x402
                failures that occur before the signature is transmitted)
    rejected  - a needs_approval row a human declined (or a hard limit blocked
                at approval time); no funds moved
    skipped   - an ALLOW where no payment was ultimately made (an x402 resource
                served for free before we paid); no funds moved
    settlement_unknown - an x402 authorization was transmitted but the HTTP
                outcome failed; the signature MAY have settled on-chain, so this
                counts toward the budget and is never retried/reverted

When a human approves a pending row, its decision is rewritten allow (the human
converted needs_approval -> allow) and status becomes executed/failed. Budget
accounting (`approved_spends`) counts decision='allow' rows except 'failed' and
'skipped' (where no money moved) — so a still-pending or rejected approval never
consumes budget, an approved+executed one does, a failed/skipped one does not,
and an x402 'settlement_unknown' does (the funds may have moved).
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime
from decimal import Decimal

from imprest.schemas.schemas import PaymentRequest, PolicyDecision


class AuditLog:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        # check_same_thread=False + a lock: the MCP runtime may execute tools on
        # the event loop today, but a future threadpool/async move must not turn
        # this into a crash. All access goes through self._lock.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts         TEXT    NOT NULL,
                    agent_id   TEXT    NOT NULL,
                    recipient  TEXT    NOT NULL,
                    amount     TEXT    NOT NULL,   -- Decimal as text: exact precision
                    asset      TEXT    NOT NULL DEFAULT 'ETH',  -- ETH or token symbol
                    operation  TEXT    NOT NULL DEFAULT 'transfer',  -- transfer/approve
                    reason     TEXT,
                    decision   TEXT    NOT NULL,   -- allow / deny / needs_approval
                    rule       TEXT    NOT NULL,
                    detail     TEXT,
                    status     TEXT    NOT NULL DEFAULT 'recorded',  -- see status vocab below
                    tx_hash    TEXT,
                    error      TEXT,
                    approver   TEXT,            -- who resolved a needs_approval row
                    context    TEXT             -- operation context, e.g. the x402 URL
                )
                """
            )
            # Migrate older databases: add any columns a pre-existing file lacks.
            existing = {r[1] for r in self._conn.execute("PRAGMA table_info(audit)")}
            if "asset" not in existing:
                self._conn.execute(
                    "ALTER TABLE audit ADD COLUMN asset TEXT NOT NULL DEFAULT 'ETH'"
                )
            if "operation" not in existing:
                self._conn.execute(
                    "ALTER TABLE audit ADD COLUMN operation TEXT NOT NULL "
                    "DEFAULT 'transfer'"
                )
            if "approver" not in existing:
                self._conn.execute("ALTER TABLE audit ADD COLUMN approver TEXT")
            if "context" not in existing:
                self._conn.execute("ALTER TABLE audit ADD COLUMN context TEXT")
            # budget queries filter by agent + recency; index makes them O(log n).
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit (agent_id, ts)"
            )
            self._conn.commit()

    def record(
        self,
        request: PaymentRequest,
        decision: PolicyDecision,
        now: datetime,
        status: str = "recorded",
        tx_hash: str | None = None,
        context: str | None = None,
    ) -> int:
        """Insert an attempt and return its row id (used to stamp the outcome later)."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO audit (ts, agent_id, recipient, amount, asset, operation, "
                "reason, decision, rule, detail, status, tx_hash, context) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    now.isoformat(),
                    request.agent_id,
                    request.recipient,
                    str(request.amount),
                    request.asset,
                    request.operation,
                    request.reason,
                    decision.decision.value,
                    decision.rule,
                    decision.reason,
                    status,
                    tx_hash,
                    context,
                ),
            )
            self._conn.commit()
            return cur.lastrowid

    def mark_executed(self, row_id: int, tx_hash: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE audit SET status = 'executed', tx_hash = ? WHERE id = ?",
                (tx_hash, row_id),
            )
            self._conn.commit()

    def mark_failed(self, row_id: int, error: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE audit SET status = 'failed', error = ? WHERE id = ?",
                (error, row_id),
            )
            self._conn.commit()

    def mark_skipped(self, row_id: int, note: str) -> None:
        """An ALLOW where no payment was ultimately made (e.g. an x402 resource
        became free before we paid). Excluded from budget — nothing was spent."""
        with self._lock:
            self._conn.execute(
                "UPDATE audit SET status = 'skipped', error = ? WHERE id = ?",
                (note, row_id),
            )
            self._conn.commit()

    def mark_settlement_unknown(self, row_id: int, error: str) -> None:
        """An x402 authorization was transmitted but the outcome is unknown.

        The signed authorization may have been settled on-chain by the payee's
        facilitator regardless of the HTTP reply, so — unlike 'failed' — this
        status COUNTS toward the budget (approved_spends includes it). It is
        terminal: the row is never rolled back to pending for a free retry."""
        with self._lock:
            self._conn.execute(
                "UPDATE audit SET status = 'settlement_unknown', error = ? "
                "WHERE id = ?",
                (error, row_id),
            )
            self._conn.commit()

    # --- approval-completion flow ---------------------------------------------

    def pending_approvals(self, agent_id: str | None = None) -> list[dict]:
        """needs_approval rows still awaiting a human decision (status=recorded)."""
        cols = ["id", "ts", "agent_id", "recipient", "amount", "asset",
                "operation", "detail", "context"]
        # cols are hardcoded literals; every runtime value binds via ? params.
        sql = (f"SELECT {', '.join(cols)} FROM audit "  # nosec B608
               "WHERE decision = 'needs_approval' AND status = 'recorded'")
        params: list = []
        if agent_id:
            sql += " AND agent_id = ?"
            params.append(agent_id)
        sql += " ORDER BY id"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [dict(zip(cols, r)) for r in rows]

    def get_pending(self, row_id: int) -> dict | None:
        """Fetch one still-pending approval by id, or None if it isn't pending."""
        cols = ["id", "agent_id", "recipient", "amount", "asset", "operation",
                "reason", "context"]
        with self._lock:
            row = self._conn.execute(
                # cols are hardcoded literals; the id binds via the ? param.
                f"SELECT {', '.join(cols)} FROM audit "  # nosec B608
                "WHERE id = ? AND decision = 'needs_approval' AND status = 'recorded'",
                (row_id,),
            ).fetchone()
        return dict(zip(cols, row)) if row else None

    def mark_approved(self, row_id: int, approver: str) -> None:
        """A human approved: rewrite needs_approval -> allow and stamp the approver.

        Status stays 'recorded'; the caller then stamps the send outcome with the
        existing mark_executed/mark_failed. Once decision='allow' the row counts
        toward the budget (even before a send, mirroring allow-with-sends-off).
        """
        with self._lock:
            self._conn.execute(
                "UPDATE audit SET decision = 'allow', approver = ? WHERE id = ?",
                (approver, row_id),
            )
            self._conn.commit()

    def revert_to_pending(self, row_id: int, error: str) -> None:
        """Undo a failed approval attempt so an operator can retry.

        A resolved approval flips the row to allow BEFORE the send (record before
        act). If the send then raises, we roll the row back to needs_approval /
        recorded — otherwise get_pending would never see it again and the human's
        decision would be lost to a transient RPC blip. The last error is kept.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE audit SET decision = 'needs_approval', status = 'recorded', "
                "approver = NULL, error = ? WHERE id = ?",
                (error, row_id),
            )
            self._conn.commit()

    def mark_rejected(self, row_id: int, approver: str, note: str = "") -> None:
        """A human declined (or a hard limit blocked at approval time)."""
        with self._lock:
            self._conn.execute(
                "UPDATE audit SET status = 'rejected', approver = ?, error = ? "
                "WHERE id = ?",
                (approver, note or None, row_id),
            )
            self._conn.commit()

    def history(self, agent_id: str | None = None) -> list[dict]:
        """Return audit rows, optionally filtered to one agent, oldest first."""
        cols = ["ts", "agent_id", "recipient", "amount", "asset", "operation",
                "decision", "rule", "detail", "status", "tx_hash", "error",
                "approver"]
        # cols are hardcoded literals; agent_id binds via the ? param.
        select = f"SELECT {', '.join(cols)} FROM audit"  # nosec B608
        with self._lock:
            if agent_id:
                rows = self._conn.execute(
                    select + " WHERE agent_id = ? ORDER BY id", (agent_id,)
                ).fetchall()
            else:
                rows = self._conn.execute(select + " ORDER BY id").fetchall()
        return [dict(zip(cols, r)) for r in rows]

    def outstanding_allowances(
        self, agent_id: str
    ) -> list[tuple[str, Decimal, str]]:
        """(spender, amount, asset) for every LIVE allowance this agent granted.

        The allowance ledger. ERC-20 approve() OVERWRITES the previous value,
        so the live allowance to a spender is the amount of the LATEST approve
        that counts — decision='allow' (granted, or human-approved) and not
        failed (a failed broadcast leaves the previous on-chain value intact,
        which is why failed rows are skipped rather than treated as zero).
        Deliberately NOT time-bounded: an allowance never expires with a budget
        window. A latest value of 0 (a revoke) drops the spender entirely.

        v1 is conservative: it assumes the full last-approved amount is still
        live (the spender may have already pulled some or all of it — that
        would only mean the real liability is lower than what we cap).
        """
        sql = ("SELECT recipient, amount, asset FROM audit "
               "WHERE agent_id = ? AND operation = 'approve' "
               "AND decision = 'allow' AND status != 'failed' ORDER BY id")
        with self._lock:
            rows = self._conn.execute(sql, (agent_id,)).fetchall()
        latest: dict[tuple[str, str], Decimal] = {}
        for recipient, amount, asset in rows:
            latest[(asset, recipient.lower())] = Decimal(amount)
        return [
            (spender, amount, asset)
            for (asset, spender), amount in latest.items()
            if amount != 0
        ]

    def approved_spends(
        self, agent_id: str, since: datetime | None = None
    ) -> list[tuple[str, Decimal, datetime, str]]:
        """(recipient, amount, ts, asset) for spends that count toward the budget.

        Counts decision='allow' rows except those where no money moved:
        'failed' (send raised, funds intact) and 'skipped' (x402 resource went
        free, never paid) are excluded; 'recorded', 'executed', and
        'settlement_unknown' (an x402 signature was handed over — funds MAY have
        moved, so it must count) are included. Optionally bounded to rows
        at/after `since` (the caller passes now-24h; the widest policy window is
        daily). All assets are returned; the engine splits the budget per asset.
        """
        sql = ("SELECT recipient, amount, ts, asset FROM audit "
               "WHERE agent_id = ? AND decision = 'allow' "
               "AND status NOT IN ('failed', 'skipped')")
        params: list = [agent_id]
        if since is not None:
            sql += " AND ts >= ?"
            params.append(since.isoformat())
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [
            (r[0], Decimal(r[1]), datetime.fromisoformat(r[2]), r[3]) for r in rows
        ]
