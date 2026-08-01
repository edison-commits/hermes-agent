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
                updated_at REAL NOT NULL
            )"""
        )
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
                   idempotency_key: str | None = None) -> dict[str, Any]:
    """Create or update an idempotent receipt and return its public record."""
    if not action.strip() or not scope.strip():
        raise ValueError("action and scope are required")
    if status not in {"requested", "approved", "rejected", "blocked", "completed", "failed", "verified"}:
        raise ValueError(f"invalid receipt status: {status!r}")
    now = time.time()
    receipt_id = _receipt_id(action, scope, idempotency_key)
    evidence_list = [str(item)[:500] for item in evidence]
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
               (receipt_id, action, status, scope, evidence_json, idempotency_key, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(receipt_id) DO UPDATE SET
                 status=excluded.status, evidence_json=excluded.evidence_json, updated_at=excluded.updated_at""",
            (receipt_id, action, status, scope, json.dumps(evidence_list), idempotency_key, now, now),
        )
        row = conn.execute(
            """SELECT receipt_id, action, status, scope, evidence_json, created_at, updated_at
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
    }


def get_receipt(receipt_id: str) -> dict[str, Any]:
    with _connection() as conn:
        row = conn.execute(
            "SELECT receipt_id, action, status, scope, evidence_json, created_at, updated_at FROM action_receipts WHERE receipt_id=?",
            (receipt_id,),
        ).fetchone()
    return _row_to_dict(row)


def list_receipts(*, scope: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    with _connection() as conn:
        if scope:
            rows = conn.execute(
                "SELECT receipt_id, action, status, scope, evidence_json, created_at, updated_at FROM action_receipts WHERE scope=? ORDER BY created_at DESC LIMIT ?",
                (scope, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT receipt_id, action, status, scope, evidence_json, created_at, updated_at FROM action_receipts ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
    return [_row_to_dict(row) for row in rows]


__all__ = ["get_receipt", "list_receipts", "record_receipt"]
