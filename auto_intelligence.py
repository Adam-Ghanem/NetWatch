"""Durable, single-instance throttle for opt-in de-identified AI analysis.

Kept separate from the API request budget. A persisted claim prevents duplicate
paid calls after process restarts, and an unchanged successful evidence digest
is never sent again. Shared-service / multi-replica mode remains unsupported.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Literal

_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def _now(value: datetime | None) -> datetime:
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc)


def _database() -> sqlite3.Connection:
    import inventory_store

    return inventory_store._connect()


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS intelligence_auto_state (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            last_attempt_at TEXT NOT NULL DEFAULT '',
            last_success_at TEXT NOT NULL DEFAULT '',
            last_success_digest TEXT NOT NULL DEFAULT '',
            pending_digest TEXT NOT NULL DEFAULT '',
            last_outcome TEXT NOT NULL DEFAULT 'never'
        )
    """)


def claim_auto_analysis(
    digest: str, *, interval_seconds: int, now: datetime | None = None
) -> Literal["claimed", "unchanged", "interval"]:
    """Atomically claim one due analysis; never reset success history on failure."""
    if not _DIGEST.fullmatch(digest):
        raise ValueError("Invalid AI evidence digest.")
    interval = max(3600, min(int(interval_seconds), 86400))
    moment = _now(now)
    with _database() as conn:
        _create_schema(conn)
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT last_attempt_at, last_success_digest FROM intelligence_auto_state WHERE id = 1"
        ).fetchone()
        if row is not None:
            if row["last_success_digest"] == digest:
                return "unchanged"
            if row["last_attempt_at"]:
                try:
                    previous = datetime.fromisoformat(row["last_attempt_at"])
                    if moment < previous + timedelta(seconds=interval):
                        return "interval"
                except ValueError:
                    # Malformed legacy state should never trigger unbounded retries.
                    return "interval"
        conn.execute(
            """
            INSERT INTO intelligence_auto_state (
                id, last_attempt_at, pending_digest, last_outcome
            ) VALUES (1, ?, ?, 'in_progress')
            ON CONFLICT(id) DO UPDATE SET
                last_attempt_at=excluded.last_attempt_at,
                pending_digest=excluded.pending_digest,
                last_outcome='in_progress'
            """,
            (moment.isoformat(timespec="seconds"), digest),
        )
    return "claimed"


def finish_auto_analysis(
    digest: str, *, success: bool, now: datetime | None = None
) -> bool:
    """Persist a completed/failed claim, guarded against stale writers."""
    if not _DIGEST.fullmatch(digest):
        raise ValueError("Invalid AI evidence digest.")
    with _database() as conn:
        _create_schema(conn)
        cursor = conn.execute(
            """
            UPDATE intelligence_auto_state SET
                last_success_digest=CASE WHEN ? THEN ? ELSE last_success_digest END,
                last_success_at=CASE WHEN ? THEN ? ELSE last_success_at END,
                pending_digest='',
                last_outcome=?
            WHERE id=1 AND pending_digest=?
            """,
            (
                int(success),
                digest,
                int(success),
                _now(now).isoformat(timespec="seconds"),
                "completed" if success else "failed",
                digest,
            ),
        )
        return cursor.rowcount == 1


def auto_analysis_status() -> dict[str, str]:
    """Return only operational state, never private evidence hashes."""
    with _database() as conn:
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
