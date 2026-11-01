"""Single-instance SQLite notification receipts with at-least-once delivery.

A crash after webhook acceptance but before acknowledgement can cause replay;
consumers should deduplicate the stable event_id. No destination URLs are persisted.
"""

from __future__ import annotations

import hashlib
import json
import logging
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from notifications import (
    alert_meets_notification_threshold,
    build_alert_notification_payload,
    deliver_stored_notification,
    notification_channels,
)

LOGGER = logging.getLogger(__name__)
MAX_DELIVERY_ATTEMPTS = 8
MAX_BATCH = 20
CLAIM_STALE_SECONDS = 180


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="seconds")


def create_notification_delivery_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS notification_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            alert_id INTEGER NOT NULL,
            channel TEXT NOT NULL CHECK(channel IN ('webhook', 'slack')),
            payload TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'delivered', 'dead')),
            attempts INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            available_at TEXT NOT NULL,
            claimed_at TEXT NOT NULL DEFAULT '',
            claim_token TEXT NOT NULL DEFAULT '',
            delivered_at TEXT NOT NULL DEFAULT '',
            last_result TEXT NOT NULL DEFAULT ''
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_notification_delivery_due "
        "ON notification_deliveries(status, available_at, claimed_at, id)"
    )


def enqueue_notification_receipts(conn: sqlite3.Connection, alert: dict[str, Any]) -> int:
    """Insert deidentified, deduplicated receipts in the same transaction as the case."""
    if not alert_meets_notification_threshold(alert):
        return 0
    alert_id = int(alert.get("id", 0))
    if alert_id <= 0:
        return 0
    payload = build_alert_notification_payload({**alert, "_notification_event": "alert_created"})
    now = _iso(_now())
    created = 0
    for channel in notification_channels():
        if not channel.enabled:
            continue
        key = f"netwatch-alert:v1:{alert_id}:alert_created:{channel.kind}"
        event_id = hashlib.sha256(key.encode("ascii")).hexdigest()
        body = json.dumps({**payload, "event_id": event_id}, sort_keys=True)
        cursor = conn.execute(
            """
            INSERT INTO notification_deliveries(
                event_id, alert_id, channel, payload, created_at, available_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(event_id) DO NOTHING
            """,
            (event_id, alert_id, channel.kind, body, now, now),
        )
        created += int(cursor.rowcount == 1)
    return created


def _connect() -> sqlite3.Connection:
    import inventory_store

    return inventory_store._connect()


def process_notification_receipts_once(*, limit: int = MAX_BATCH) -> dict[str, int]:
    """Claim under a SQLite write lock, then deliver outside the transaction."""
    now = _now()
    token = secrets.token_hex(16)
    claimed: list[dict[str, Any]] = []
    with _connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            UPDATE notification_deliveries
            SET status = 'dead', claimed_at = '', claim_token = '',
                last_result = 'retry_exhausted'
            WHERE status = 'pending' AND attempts >= ?
              AND (claimed_at = '' OR claimed_at <= ?)
            """,
            (MAX_DELIVERY_ATTEMPTS, _iso(now - timedelta(seconds=CLAIM_STALE_SECONDS))),
        )
        rows = conn.execute(
            """
            SELECT * FROM notification_deliveries
            WHERE status = 'pending' AND available_at <= ?
              AND (claimed_at = '' OR claimed_at <= ?) AND attempts < ?
            ORDER BY id ASC LIMIT ?
            """,
            (
                _iso(now),
                _iso(now - timedelta(seconds=CLAIM_STALE_SECONDS)),
                MAX_DELIVERY_ATTEMPTS,
                max(1, min(int(limit), MAX_BATCH)),
            ),
        ).fetchall()
        for row in rows:
            conn.execute(
                """
                UPDATE notification_deliveries SET
                    claimed_at = ?, claim_token = ?, attempts = attempts + 1
                WHERE id = ? AND status = 'pending'
                """,
                (_iso(now), token, row["id"]),
            )
            claimed.append(dict(row))
    counters = {"claimed": len(claimed), "delivered": 0, "retry_pending": 0, "dead": 0}
    for item in claimed:
        try:
            payload = json.loads(str(item["payload"]))
            if not isinstance(payload, dict):
                raise ValueError("Stored payload is invalid.")
            status = deliver_stored_notification(str(item["channel"]), payload).status
        except Exception:
            LOGGER.error("notification_receipt_delivery_failed channel=%s", item["channel"])
            status = "failed"

        attempts = int(item["attempts"]) + 1
        deferred = status in {"disabled", "circuit_open"}
        state = (
            "delivered"
            if status == "delivered"
            else "pending" if deferred or attempts < MAX_DELIVERY_ATTEMPTS else "dead"
        )
        delay = (
            0
            if state == "delivered"
            else 300 if deferred else min(3600, 30 * 2 ** min(attempts - 1, 7))
        )
        with _connect() as conn:
            cursor = conn.execute(
                """
                UPDATE notification_deliveries SET
                    status = ?, available_at = ?, claimed_at = '', claim_token = '',
                    delivered_at = ?, last_result = ?, attempts = attempts - ?
                WHERE id = ? AND status = 'pending' AND claim_token = ?
                """,
                (
                    state,
                    _iso(_now() + timedelta(seconds=delay)),
                    _iso(_now()) if state == "delivered" else "",
                    status if status in {"delivered", "disabled", "circuit_open"} else "failed",
                    int(deferred),
                    item["id"],
                    token,
                ),
            )
        if cursor.rowcount:
            counters[
                (
                    "delivered"
                    if state == "delivered"
                    else "dead" if state == "dead" else "retry_pending"
                )
            ] += 1
    return counters


def notification_delivery_status(*, limit: int = 30) -> dict[str, Any]:
    """Return status-only receipts, never webhook URLs, payloads, or raw IP data."""
    with _connect() as conn:
        counts = conn.execute(
            "SELECT status, COUNT(*) AS count FROM notification_deliveries GROUP BY status"
        ).fetchall()
        rows = conn.execute(
            """
            SELECT event_id, alert_id, channel, status, attempts, created_at,
                   available_at, delivered_at, last_result
            FROM notification_deliveries ORDER BY id DESC LIMIT ?
            """,
            (max(1, min(int(limit), 100)),),
        ).fetchall()
    totals = {"pending": 0, "delivered": 0, "dead": 0}
    totals.update({str(row["status"]): int(row["count"]) for row in counts})
    return {"counts": totals, "receipts": [dict(row) for row in rows]}
