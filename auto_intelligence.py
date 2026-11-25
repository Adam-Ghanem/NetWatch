"""Durable, single-instance throttle for opt-in de-identified AI analysis.

Persisted claims prevent duplicate paid calls after restarts. A short lease
recovers abandoned claims, and per-attempt tokens fence stale completions.
Shared-service / multi-replica mode remains unsupported.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CLAIM_ID = re.compile(r"^[0-9a-f]{32}$")
CLAIM_LEASE_SECONDS = 180


def _now(value: datetime | None) -> datetime:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc)


@contextmanager
def _database() -> Iterator[sqlite3.Connection]:
    """Commit or roll back each state operation, then always close its SQLite handle."""
    import inventory_store

    with closing(inventory_store._connect()) as conn:
        with conn:
            yield conn


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS intelligence_auto_state (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            last_attempt_at TEXT NOT NULL DEFAULT '',
            last_success_at TEXT NOT NULL DEFAULT '',
            last_success_digest TEXT NOT NULL DEFAULT '',
            pending_digest TEXT NOT NULL DEFAULT '',
            pending_claim_id TEXT NOT NULL DEFAULT '',
            last_outcome TEXT NOT NULL DEFAULT 'never'
        )
    """)
    columns = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(intelligence_auto_state)").fetchall()
    }
    if "pending_claim_id" not in columns:
        conn.execute(
            "ALTER TABLE intelligence_auto_state "
            "ADD COLUMN pending_claim_id TEXT NOT NULL DEFAULT ''"
        )


def claim_auto_analysis(
    digest: str,
    *,
    interval_seconds: int,
    claim_id: str,
    now: datetime | None = None,
) -> Literal["claimed", "unchanged", "interval", "in_progress"]:
    """Atomically claim one due analysis with a bounded lease and fencing token."""
    if not _DIGEST.fullmatch(digest):
        raise ValueError("Invalid AI evidence digest.")
    if not _CLAIM_ID.fullmatch(claim_id):
        raise ValueError("Invalid AI analysis claim ID.")
    interval = max(3600, min(int(interval_seconds), 86400))
    moment = _now(now)
    with _database() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _create_schema(conn)
        row = conn.execute("""
            SELECT last_attempt_at, last_success_digest, pending_digest
            FROM intelligence_auto_state WHERE id = 1
            """).fetchone()
        if row is not None:
            if row["last_success_digest"] == digest:
                return "unchanged"
            last_attempt_at = str(row["last_attempt_at"] or "")
            pending_digest = str(row["pending_digest"] or "")
            if pending_digest:
                try:
                    previous = datetime.fromisoformat(last_attempt_at)
                    if previous.tzinfo is None:
                        return "in_progress"
                    previous = previous.astimezone(timezone.utc)
                except (TypeError, ValueError):
                    # An ambiguous in-progress claim must not trigger another paid call.
                    return "in_progress"
                if moment < previous + timedelta(seconds=CLAIM_LEASE_SECONDS):
                    return "in_progress"
                # The lease expired. A new token takes ownership and fences the old worker.
            elif last_attempt_at:
                try:
                    previous = datetime.fromisoformat(last_attempt_at)
                    if previous.tzinfo is None:
                        return "interval"
                    previous = previous.astimezone(timezone.utc)
                    if moment < previous + timedelta(seconds=interval):
                        return "interval"
                except (TypeError, ValueError):
                    # Malformed legacy state should never trigger unbounded retries.
                    return "interval"
        conn.execute(
            """
            INSERT INTO intelligence_auto_state (
                id, last_attempt_at, pending_digest, pending_claim_id, last_outcome
            ) VALUES (1, ?, ?, ?, 'in_progress')
            ON CONFLICT(id) DO UPDATE SET
                last_attempt_at=excluded.last_attempt_at,
                pending_digest=excluded.pending_digest,
                pending_claim_id=excluded.pending_claim_id,
                last_outcome='in_progress'
            """,
            (moment.isoformat(timespec="seconds"), digest, claim_id),
        )
    return "claimed"


def finish_auto_analysis(
    digest: str,
    *,
    claim_id: str,
    success: bool,
    now: datetime | None = None,
) -> bool:
    """Finish only the exact claim token that still owns the pending row."""
    if not _DIGEST.fullmatch(digest):
        raise ValueError("Invalid AI evidence digest.")
    if not _CLAIM_ID.fullmatch(claim_id):
        raise ValueError("Invalid AI analysis claim ID.")
    with _database() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _create_schema(conn)
        cursor = conn.execute(
            """
            UPDATE intelligence_auto_state SET
                last_success_digest=CASE WHEN ? THEN ? ELSE last_success_digest END,
                last_success_at=CASE WHEN ? THEN ? ELSE last_success_at END,
                pending_digest='',
                pending_claim_id='',
                last_outcome=?
            WHERE id=1 AND pending_digest=? AND pending_claim_id=?
            """,
            (
                int(success),
                digest,
                int(success),
                _now(now).isoformat(timespec="seconds"),
                "completed" if success else "failed",
                digest,
                claim_id,
            ),
        )
        return cursor.rowcount == 1


def auto_analysis_status() -> dict[str, str]:
    """Return only operational state, never private evidence hashes or claim tokens."""
    with _database() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _create_schema(conn)
        row = conn.execute(
            "SELECT last_attempt_at, last_success_at, last_outcome "
            "FROM intelligence_auto_state WHERE id=1"
        ).fetchone()
    return {
        "last_attempt_at": row["last_attempt_at"] if row else "",
        "last_success_at": row["last_success_at"] if row else "",
        "last_outcome": row["last_outcome"] if row else "never",
    }
