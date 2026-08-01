"""Durable receipts for side-effectful Hermes actions.

Receipts are intentionally small and local. They record what Hermes attempted,
its scope, the outcome, and verification evidence without storing full prompts
or secrets. The table lives beside the existing state.db ledgers.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Any, Iterator

from hermes_constants import get_hermes_home


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    path = get_hermes_home() / "state.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    try:
        try:
            from hermes_state import apply_wal_with_fallback
            apply_wal_with_fallback(conn, db_label="state.db (action_receipts)")
        except Exception:
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS action_receipts (
                receipt_id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                scope TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                idempotency_key TEXT UNIQUE,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                provenance_source TEXT,
                evidence_kind TEXT,
                evidence_ref TEXT,
                originator TEXT,
                accountable_party TEXT,
                parent_receipt_id TEXT
            )"""
        )
        existing = {row[1] for row in conn.execute("PRAGMA table_info(action_receipts)")}
        for name, definition in (
            ("provenance_source", "TEXT"),
            ("evidence_kind", "TEXT"),
            ("evidence_ref", "TEXT"),
            ("originator", "TEXT"),
            ("accountable_party", "TEXT"),
            ("parent_receipt_id", "TEXT"),
        ):
            if name not in existing:
                conn.execute(f"ALTER TABLE action_receipts ADD COLUMN {name} {definition}")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _receipt_id(action: str, scope: str, idempotency_key: str | None) -> str:
    if idempotency_key:
        return hashlib.sha256(f"{scope}|{action}|{idempotency_key}".encode()).hexdigest()[:24]
    return uuid.uuid4().hex[:24]


def record_receipt(*, action: str, status: str, scope: str,
                   evidence: list[str] | tuple[str, ...] = (),
                   idempotency_key: str | None = None,
                   provenance_source: str | None = None,
                   evidence_kind: str | None = None,
                   evidence_ref: str | None = None,
                   originator: str | None = None,
                   accountable_party: str | None = None,
                   parent_receipt_id: str | None = None,
                   strict_attribution: bool = False) -> dict[str, Any]:
    """Create or update an idempotent receipt and return its public record."""
    if not action.strip() or not scope.strip():
        raise ValueError("action and scope are required")
    if status not in {"requested", "approved", "rejected", "blocked", "completed", "failed", "verified"}:
        raise ValueError(f"invalid receipt status: {status!r}")
    if strict_attribution and provenance_source:
        from tools.safety_policy import attribution_decision
        if not attribution_decision(provenance_source, strict=True).allow:
            raise ValueError("precise attribution is required for this action")
    now = time.time()
    receipt_id = _receipt_id(action, scope, idempotency_key)
    evidence_list = [str(item)[:500] for item in evidence]
    if evidence_kind and not evidence_list:
        evidence_list = [evidence_kind[:500]]
    with _connection() as conn:
        if idempotency_key:
            row = conn.execute(
                "SELECT receipt_id FROM action_receipts WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if row:
                receipt_id = row[0]
        conn.execute(
            """INSERT INTO action_receipts
               (receipt_id, action, status, scope, evidence_json, idempotency_key, created_at, updated_at,
                provenance_source, evidence_kind, evidence_ref, originator, accountable_party, parent_receipt_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(receipt_id) DO UPDATE SET
                 status=excluded.status, evidence_json=excluded.evidence_json, updated_at=excluded.updated_at,
                 provenance_source=excluded.provenance_source, evidence_kind=excluded.evidence_kind,
                 evidence_ref=excluded.evidence_ref, originator=excluded.originator,
                 accountable_party=excluded.accountable_party, parent_receipt_id=excluded.parent_receipt_id""",
            (receipt_id, action, status, scope, json.dumps(evidence_list), idempotency_key, now, now,
             provenance_source, evidence_kind, evidence_ref, originator, accountable_party, parent_receipt_id),
        )
        row = conn.execute(
            """SELECT receipt_id, action, status, scope, evidence_json, created_at, updated_at,
                      provenance_source, evidence_kind, evidence_ref, originator, accountable_party, parent_receipt_id
               FROM action_receipts WHERE receipt_id=?""",
            (receipt_id,),
        ).fetchone()
    return _row_to_dict(row)


def _row_to_dict(row: tuple[Any, ...] | None) -> dict[str, Any]:
    if row is None:
        return {}
    return {
        "receipt_id": row[0], "action": row[1], "status": row[2], "scope": row[3],
        "evidence": json.loads(row[4]), "created_at": row[5], "updated_at": row[6],
        "provenance_source": row[7], "evidence_kind": row[8], "evidence_ref": row[9],
        "originator": row[10], "accountable_party": row[11], "parent_receipt_id": row[12],
    }


def get_receipt(receipt_id: str) -> dict[str, Any]:
    with _connection() as conn:
        row = conn.execute(
            """SELECT receipt_id, action, status, scope, evidence_json, created_at, updated_at,
                      provenance_source, evidence_kind, evidence_ref, originator, accountable_party, parent_receipt_id
               FROM action_receipts WHERE receipt_id=?""",
            (receipt_id,),
        ).fetchone()
    return _row_to_dict(row)


def list_receipts(*, scope: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with _connection() as conn:
        if scope:
            rows = conn.execute(
                """SELECT receipt_id, action, status, scope, evidence_json, created_at, updated_at,
                          provenance_source, evidence_kind, evidence_ref, originator, accountable_party, parent_receipt_id
                   FROM action_receipts WHERE scope=? ORDER BY created_at DESC LIMIT ?""",
                (scope, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT receipt_id, action, status, scope, evidence_json, created_at, updated_at,
                          provenance_source, evidence_kind, evidence_ref, originator, accountable_party, parent_receipt_id
                   FROM action_receipts ORDER BY created_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
    return [_row_to_dict(row) for row in rows]


__all__ = ["get_receipt", "list_receipts", "record_receipt"]
