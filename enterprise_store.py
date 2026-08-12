"""Durable event and job primitives shared by local and future enterprise workers."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

OUTBOX_MAX_ATTEMPTS = 12
JOB_MAX_ATTEMPTS = 8
CLAIM_STALE_SECONDS = 300


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_enterprise_schema(conn: sqlite3.Connection) -> None:
    """Create durable outbox/job tables without changing existing product tables."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS enterprise_outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            available_at TEXT NOT NULL,
            claimed_at TEXT NOT NULL DEFAULT '',
            claimed_by TEXT NOT NULL DEFAULT '',
            delivered_at TEXT NOT NULL DEFAULT '',
            attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            last_error TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default',
            topic TEXT NOT NULL,
            event_type TEXT NOT NULL,
            aggregate_id TEXT NOT NULL,
            dedupe_key TEXT NOT NULL UNIQUE,
            payload TEXT NOT NULL
        )
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS enterprise_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            available_at TEXT NOT NULL,
            claimed_at TEXT NOT NULL DEFAULT '',
            claimed_by TEXT NOT NULL DEFAULT '',
            completed_at TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'running', 'succeeded', 'failed')),
            attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            max_attempts INTEGER NOT NULL DEFAULT 8 CHECK (max_attempts BETWEEN 1 AND 20),
            last_error TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default',
            job_type TEXT NOT NULL,
            dedupe_key TEXT NOT NULL UNIQUE,
            payload TEXT NOT NULL
        )
        """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_enterprise_outbox_pending "
        "ON enterprise_outbox(delivered_at, available_at, id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_enterprise_jobs_pending "
        "ON enterprise_jobs(status, available_at, id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_enterprise_events_tenant "
        "ON enterprise_outbox(tenant_id, id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_enterprise_jobs_tenant " "ON enterprise_jobs(tenant_id, id)"
    )


def _stale_cutoff(current: str) -> str:
    try:
        moment = datetime.fromisoformat(current.replace("Z", "+00:00"))
    except ValueError:
        moment = datetime.now(timezone.utc)
    return (moment - timedelta(seconds=CLAIM_STALE_SECONDS)).isoformat(timespec="seconds")


def _json_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _decode(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    try:
        item["payload"] = json.loads(str(item["payload"]))
    except (TypeError, ValueError):
        item["payload"] = {}
    return item


def enqueue_outbox_event(
    conn: sqlite3.Connection,
    *,
    topic: str,
    event_type: str,
    aggregate_id: str,
    dedupe_key: str,
    payload: dict[str, Any],
    tenant_id: str = "default",
    available_at: str | None = None,
) -> int:
    """Insert one idempotent event inside the caller's transaction."""
    now = _utc_now()
    cursor = conn.execute(
        """
        INSERT INTO enterprise_outbox (
            created_at, available_at, tenant_id, topic, event_type,
            aggregate_id, dedupe_key, payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(dedupe_key) DO NOTHING
        """,
        (
            now,
            available_at or now,
            str(tenant_id)[:120] or "default",
            str(topic)[:120],
            str(event_type)[:120],
            str(aggregate_id)[:200],
            str(dedupe_key)[:240],
            _json_payload(payload),
        ),
    )
    if cursor.rowcount == 1 and cursor.lastrowid is not None:
        return int(cursor.lastrowid)
    row = conn.execute(
        "SELECT id FROM enterprise_outbox WHERE dedupe_key = ?", (str(dedupe_key)[:240],)
    ).fetchone()
    if row is None:
        raise RuntimeError("Outbox event was not created or recovered.")
    return int(row["id"])


def claim_outbox_events(
    conn: sqlite3.Connection,
    *,
    consumer_id: str,
    limit: int = 100,
    now: str | None = None,
) -> list[dict[str, Any]]:
    """Claim pending events; stale claims become eligible for another worker."""
    current = now or _utc_now()
    safe_limit = max(1, min(int(limit), 500))
    stale_cutoff = _stale_cutoff(current)
    rows = conn.execute(
        """
        SELECT * FROM enterprise_outbox
        WHERE delivered_at = '' AND available_at <= ?
          AND (claimed_at = '' OR claimed_at <= ?)
          AND attempts < ?
        ORDER BY id ASC LIMIT ?
        """,
        (current, stale_cutoff, OUTBOX_MAX_ATTEMPTS, safe_limit),
    ).fetchall()
    claimed: list[dict[str, Any]] = []
    for row in rows:
        cursor = conn.execute(
            """
            UPDATE enterprise_outbox
            SET claimed_at = ?, claimed_by = ?, attempts = attempts + 1
            WHERE id = ? AND delivered_at = ''
              AND (claimed_at = '' OR claimed_at <= ?)
            """,
            (current, str(consumer_id)[:120], row["id"], stale_cutoff),
        )
        if cursor.rowcount == 1:
            refreshed = conn.execute(
                "SELECT * FROM enterprise_outbox WHERE id = ?", (row["id"],)
            ).fetchone()
            if refreshed is not None:
                claimed.append(_decode(refreshed))
    return claimed


def mark_outbox_delivered(
    conn: sqlite3.Connection, *, event_id: int, consumer_id: str, delivered_at: str | None = None
) -> bool:
    cursor = conn.execute(
        """
        UPDATE enterprise_outbox
        SET delivered_at = ?, claimed_at = '', claimed_by = '', last_error = ''
        WHERE id = ? AND claimed_by = ? AND delivered_at = ''
        """,
        (delivered_at or _utc_now(), event_id, str(consumer_id)[:120]),
    )
    return cursor.rowcount == 1


def mark_outbox_failed(
    conn: sqlite3.Connection,
    *,
    event_id: int,
    consumer_id: str,
    error: str,
    retry_at: str | None = None,
) -> bool:
    cursor = conn.execute(
        """
        UPDATE enterprise_outbox
        SET available_at = ?, claimed_at = '', claimed_by = '', last_error = ?
        WHERE id = ? AND claimed_by = ? AND delivered_at = ''
        """,
        (
            retry_at or _utc_now(),
            " ".join(str(error).split())[:500],
            event_id,
            str(consumer_id)[:120],
        ),
    )
    return cursor.rowcount == 1


def enqueue_job(
    conn: sqlite3.Connection,
    *,
    job_type: str,
    dedupe_key: str,
    payload: dict[str, Any],
    tenant_id: str = "default",
    available_at: str | None = None,
    max_attempts: int = JOB_MAX_ATTEMPTS,
) -> int:
    now = _utc_now()
    safe_attempts = max(1, min(int(max_attempts), 20))
    cursor = conn.execute(
        """
        INSERT INTO enterprise_jobs (
            created_at, available_at, tenant_id, job_type, dedupe_key, payload, max_attempts
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(dedupe_key) DO NOTHING
        """,
        (
            now,
            available_at or now,
            str(tenant_id)[:120] or "default",
            str(job_type)[:120],
            str(dedupe_key)[:240],
            _json_payload(payload),
            safe_attempts,
        ),
    )
    if cursor.rowcount == 1 and cursor.lastrowid is not None:
        return int(cursor.lastrowid)
    row = conn.execute(
        "SELECT id FROM enterprise_jobs WHERE dedupe_key = ?", (str(dedupe_key)[:240],)
    ).fetchone()
    if row is None:
        raise RuntimeError("Job was not created or recovered.")
    return int(row["id"])


def claim_jobs(
    conn: sqlite3.Connection,
    *,
    worker_id: str,
    job_type: str | None = None,
    limit: int = 10,
    now: str | None = None,
) -> list[dict[str, Any]]:
    current = now or _utc_now()
    safe_limit = max(1, min(int(limit), 100))
    stale_cutoff = _stale_cutoff(current)
    rows = conn.execute(
        """
        SELECT * FROM enterprise_jobs
        WHERE status IN ('pending', 'running') AND available_at <= ?
          AND (claimed_at = '' OR claimed_at <= ?)
          AND attempts < max_attempts
          AND (? IS NULL OR job_type = ?)
        ORDER BY id ASC LIMIT ?
        """,
        (current, stale_cutoff, job_type, job_type, safe_limit),
    ).fetchall()
    claimed: list[dict[str, Any]] = []
    for row in rows:
        cursor = conn.execute(
            """
            UPDATE enterprise_jobs
            SET status = 'running', claimed_at = ?, claimed_by = ?, attempts = attempts + 1
            WHERE id = ? AND status IN ('pending', 'running')
              AND (claimed_at = '' OR claimed_at <= ?)
            """,
            (current, str(worker_id)[:120], row["id"], stale_cutoff),
        )
        if cursor.rowcount == 1:
            refreshed = conn.execute(
                "SELECT * FROM enterprise_jobs WHERE id = ?", (row["id"],)
            ).fetchone()
            if refreshed is not None:
                claimed.append(_decode(refreshed))
    return claimed


def complete_job(conn: sqlite3.Connection, *, job_id: int, worker_id: str) -> bool:
    cursor = conn.execute(
        """
        UPDATE enterprise_jobs
        SET status = 'succeeded', completed_at = ?, claimed_at = '',
            claimed_by = '', last_error = ''
        WHERE id = ? AND status = 'running' AND claimed_by = ?
        """,
        (_utc_now(), job_id, str(worker_id)[:120]),
    )
    return cursor.rowcount == 1


def fail_job(
    conn: sqlite3.Connection,
    *,
    job_id: int,
    worker_id: str,
    error: str,
    retry_at: str | None = None,
) -> bool:
    cursor = conn.execute(
        """
        UPDATE enterprise_jobs
        SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'pending' END,
            available_at = ?, claimed_at = '', claimed_by = '', last_error = ?
        WHERE id = ? AND status = 'running' AND claimed_by = ?
        """,
        (
            retry_at or _utc_now(),
            " ".join(str(error).split())[:500],
            job_id,
            str(worker_id)[:120],
        ),
    )
    return cursor.rowcount == 1


def enterprise_queue_status(conn: sqlite3.Connection) -> dict[str, int]:
    outbox = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN delivered_at = '' THEN 1 ELSE 0 END) AS pending,
            SUM(CASE WHEN delivered_at != '' THEN 1 ELSE 0 END) AS delivered,
            SUM(CASE WHEN attempts >= ? AND delivered_at = '' THEN 1 ELSE 0 END) AS dead_letter
        FROM enterprise_outbox
        """,
        (OUTBOX_MAX_ATTEMPTS,),
    ).fetchone()
    jobs = conn.execute("""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status IN ('pending', 'running') THEN 1 ELSE 0 END) AS active,
            SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END) AS succeeded,
            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed
        FROM enterprise_jobs
        """).fetchone()
    return {
        "outbox_total": int(outbox["total"] or 0),
        "outbox_pending": int(outbox["pending"] or 0),
        "outbox_delivered": int(outbox["delivered"] or 0),
        "outbox_dead_letter": int(outbox["dead_letter"] or 0),
        "jobs_total": int(jobs["total"] or 0),
        "jobs_active": int(jobs["active"] or 0),
        "jobs_succeeded": int(jobs["succeeded"] or 0),
        "jobs_failed": int(jobs["failed"] or 0),
    }
