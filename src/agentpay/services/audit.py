"""Append-only audit log.

Every payment attempt — approved, denied, or executed — is recorded. For a
spend-control product this log IS half the value: "show me everything my agent
tried to spend, and what your policy did about it."

SQLite because it's zero-setup, append-only in spirit, and easy to query. The
table is never updated in place; we only INSERT.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from decimal import Decimal

from agentpay.schemas.schemas import PaymentRequest, PolicyDecision


class AuditLog:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT    NOT NULL,
                agent_id   TEXT    NOT NULL,
                recipient  TEXT    NOT NULL,
                amount     TEXT    NOT NULL,   -- Decimal stored as text to keep precision
                reason     TEXT,
                decision   TEXT    NOT NULL,   -- allow / deny / needs_approval
                rule       TEXT    NOT NULL,   -- which guardrail fired
                detail     TEXT,               -- human-readable explanation
                tx_hash    TEXT                -- set once/if the payment actually executes
            )
            """
        )
        self._conn.commit()

    def record(
        self,
        request: PaymentRequest,
        decision: PolicyDecision,
        now: datetime,
        tx_hash: str | None = None,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO audit (ts, agent_id, recipient, amount, reason, decision, rule, detail, tx_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                now.isoformat(),
                request.agent_id,
                request.recipient,
                str(request.amount),
                request.reason,
                decision.decision.value,
                decision.rule,
                decision.reason,
                tx_hash,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def history(self, agent_id: str | None = None) -> list[dict]:
        """Return audit rows, optionally filtered to one agent, newest last."""
        if agent_id:
            rows = self._conn.execute(
                "SELECT ts, agent_id, recipient, amount, decision, rule, detail, tx_hash "
                "FROM audit WHERE agent_id = ? ORDER BY id",
                (agent_id,),
            )
        else:
            rows = self._conn.execute(
                "SELECT ts, agent_id, recipient, amount, decision, rule, detail, tx_hash "
                "FROM audit ORDER BY id"
            )
        cols = ["ts", "agent_id", "recipient", "amount", "decision", "rule", "detail", "tx_hash"]
        return [dict(zip(cols, r)) for r in rows.fetchall()]

    def approved_spends(self, agent_id: str) -> list[tuple[str, Decimal, datetime]]:
        """(recipient, amount, ts) for payments that were allowed — feeds the policy engine's history."""
        rows = self._conn.execute(
            "SELECT recipient, amount, ts FROM audit "
            "WHERE agent_id = ? AND decision IN ('allow', 'needs_approval')",
            (agent_id,),
        )
        return [
            (r[0], Decimal(r[1]), datetime.fromisoformat(r[2])) for r in rows.fetchall()
        ]
