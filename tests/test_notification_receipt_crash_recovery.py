"""Regression coverage for durable receipt crash recovery and claim fencing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import inventory_store
import notification_outbox as outbox
import notifications


def _setup(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    inventory_store.init_db()
    monkeypatch.setenv("NETWATCH_WEBHOOK_URL", "https://hooks.example.test/receiver")
    monkeypatch.delenv("NETWATCH_SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("NETWATCH_NOTIFY_MIN_SEVERITY", "High")
    monkeypatch.setenv("NETWATCH_NOTIFY_INCLUDE_RAW_TARGETS", "false")
    notifications._reset_notification_state_for_tests()
    with inventory_store._connect() as conn:
        assert outbox.enqueue_notification_receipts(
            conn, {"id": 451, "severity": "Critical", "status": "open"}
        ) == 1


def _stale_time():
    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def test_stale_claim_is_recovered_without_duplicate_receipt(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    with inventory_store._connect() as conn:
        conn.execute(
            "UPDATE notification_deliveries SET claimed_at = ?, "
            "claim_token = 'crashed-worker', attempts = 1",
            (_stale_time(),),
        )
    sent = []

    def deliver(kind, payload):
        sent.append(payload["event_id"])
        return notifications.ChannelNotificationResult(kind, "delivered", 1)

    monkeypatch.setattr(outbox, "deliver_stored_notification", deliver)
    result = outbox.process_notification_receipts_once()
    assert result["delivered"] == 1
    assert len(sent) == 1
    assert outbox.process_notification_receipts_once()["claimed"] == 0
    with inventory_store._connect() as conn:
        row = conn.execute(
            "SELECT status, attempts, claim_token FROM notification_deliveries"
        ).fetchone()
    assert tuple(row) == ("delivered", 2, "")


def test_exhausted_stale_claim_becomes_dead_without_delivery(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    with inventory_store._connect() as conn:
        conn.execute(
            "UPDATE notification_deliveries SET claimed_at = ?, "
            "claim_token = 'crashed-worker', attempts = ?",
            (_stale_time(), outbox.MAX_DELIVERY_ATTEMPTS),
        )
    sent = []
    monkeypatch.setattr(
        outbox, "deliver_stored_notification", lambda *args: sent.append(args)
    )
    assert outbox.process_notification_receipts_once()["claimed"] == 0
    assert sent == []
    with inventory_store._connect() as conn:
        row = conn.execute(
            "SELECT status, last_result, claim_token FROM notification_deliveries"
        ).fetchone()
    assert tuple(row) == ("dead", "retry_exhausted", "")


def test_old_worker_cannot_ack_after_receipt_is_reclaimed(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    deliveries = []

    def deliver(kind, payload):
        deliveries.append(payload["event_id"])
        if len(deliveries) == 1:
            with inventory_store._connect() as conn:
                conn.execute(
                    "UPDATE notification_deliveries SET claimed_at = ?",
                    (_stale_time(),),
                )
            nested = outbox.process_notification_receipts_once()
            assert nested["delivered"] == 1
        return notifications.ChannelNotificationResult(kind, "delivered", 1)

    monkeypatch.setattr(outbox, "deliver_stored_notification", deliver)
    outer = outbox.process_notification_receipts_once()
    assert outer["claimed"] == 1
    assert outer["delivered"] == 0
    assert len(deliveries) == 2  # At-least-once delivery after lease expiry.
    with inventory_store._connect() as conn:
        row = conn.execute(
            "SELECT status, attempts, claim_token FROM notification_deliveries"
        ).fetchone()
    assert tuple(row) == ("delivered", 2, "")
