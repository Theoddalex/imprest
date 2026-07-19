"""Tests for the audit log: precision, timezone contract, status filtering, threads."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from imprest.schemas.schemas import Decision, PaymentRequest, PolicyDecision
from imprest.services.audit import AuditLog

ALLOW = PolicyDecision(Decision.ALLOW, "within policy", "ok")
DENY = PolicyDecision(Decision.DENY, "nope", "per_transaction_max")
APPROVE = PolicyDecision(Decision.NEEDS_APPROVAL, "human", "approval_threshold")


def req(amount: str, agent="agent-1"):
    return PaymentRequest(agent_id=agent, recipient="0x" + "a" * 40, amount=Decimal(amount))


def test_decimal_precision_survives_round_trip(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    now = datetime.now(timezone.utc)
    audit.record(req("0.123456789012345678"), ALLOW, now)
    (_, amount, _, _) = audit.approved_spends("agent-1")[0]
    assert amount == Decimal("0.123456789012345678")  # no float drift


def test_timestamps_come_back_tz_aware_and_comparable(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    now = datetime.now(timezone.utc)
    audit.record(req("0.01"), ALLOW, now)
    (_, _, ts, _) = audit.approved_spends("agent-1")[0]
    assert ts.tzinfo is not None
    # the exact comparison the policy engine does — must not raise
    assert ts >= now - timedelta(hours=1)


def test_approved_spends_excludes_denied_and_needs_approval(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    now = datetime.now(timezone.utc)
    audit.record(req("0.01"), ALLOW, now)
    audit.record(req("0.10"), DENY, now)
    audit.record(req("0.03"), APPROVE, now)
    spends = audit.approved_spends("agent-1")
    assert [a for _, a, _, _ in spends] == [Decimal("0.01")]


def test_failed_send_excluded_from_budget(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    now = datetime.now(timezone.utc)
    row = audit.record(req("0.01"), ALLOW, now)
    audit.mark_failed(row, "rpc boom")
    assert audit.approved_spends("agent-1") == []


def test_since_filter_bounds_the_window(tmp_path):
    audit = AuditLog(str(tmp_path / "a.db"))
    now = datetime.now(timezone.utc)
    audit.record(req("0.01"), ALLOW, now - timedelta(hours=30))  # old
    audit.record(req("0.02"), ALLOW, now)                        # recent
    recent = audit.approved_spends("agent-1", since=now - timedelta(hours=24))
    assert [a for _, a, _, _ in recent] == [Decimal("0.02")]


def _make_legacy_db(path):
    """A pre-ERC-20 audit table: no asset / operation / approver columns."""
    c = sqlite3.connect(path)
    c.execute(
        """CREATE TABLE audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            agent_id TEXT NOT NULL, recipient TEXT NOT NULL, amount TEXT NOT NULL,
            reason TEXT, decision TEXT NOT NULL, rule TEXT NOT NULL, detail TEXT,
            status TEXT NOT NULL DEFAULT 'recorded', tx_hash TEXT, error TEXT
        )"""
    )
    now = datetime.now(timezone.utc).isoformat()
    c.execute(
        "INSERT INTO audit (ts, agent_id, recipient, amount, reason, decision, "
        "rule, detail, status) VALUES (?,?,?,?,?,?,?,?,?)",
        (now, "agent-1", "0x" + "a" * 40, "0.01", "legacy", "allow", "ok",
         "within", "recorded"),
    )
    c.commit()
    c.close()


def test_opening_a_legacy_db_adds_missing_columns(tmp_path):
    p = str(tmp_path / "legacy.db")
    _make_legacy_db(p)
    AuditLog(p)  # migration runs on open
    cols = {r[1] for r in sqlite3.connect(p).execute("PRAGMA table_info(audit)")}
    assert {"asset", "operation", "approver"} <= cols


def test_legacy_rows_read_back_with_defaults(tmp_path):
    p = str(tmp_path / "legacy.db")
    _make_legacy_db(p)
    audit = AuditLog(p)
    # the pre-existing allow row still surfaces, defaulted, not NULL/crashed
    (recipient, amount, _, asset) = audit.approved_spends("agent-1")[0]
    assert amount == Decimal("0.01") and asset == "ETH"
    row = audit.history("agent-1")[0]
    assert row["asset"] == "ETH" and row["operation"] == "transfer"


def test_reopening_a_migrated_db_is_idempotent(tmp_path):
    p = str(tmp_path / "legacy.db")
    _make_legacy_db(p)
    AuditLog(p)
    AuditLog(p)  # second open must not re-ADD columns or raise
    now = datetime.now(timezone.utc)
    audit = AuditLog(p)
    audit.record(req("0.02"), ALLOW, now)  # still writable
    assert len(audit.history("agent-1")) == 2


def test_usable_from_a_worker_thread(tmp_path):
    # guards against the check_same_thread crash if tools ever move to a threadpool
    audit = AuditLog(str(tmp_path / "a.db"))
    now = datetime.now(timezone.utc)
    err = {}

    def work():
        try:
            audit.record(req("0.01"), ALLOW, now)
        except Exception as e:  # noqa: BLE001
            err["e"] = e

    t = threading.Thread(target=work)
    t.start()
    t.join()
    assert "e" not in err
    assert len(audit.history("agent-1")) == 1
