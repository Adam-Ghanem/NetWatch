"""Offline regressions for durable notification retry exhaustion.

All deliveries are synthetic; no webhook or network request is performed.
"""

from __future__ import annotations

from datetime import timedelta

import inventory_store
import notification_outbox as outbox
import notifications


def _queued_receipt(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    inventory_store.init_db()
    monkeypatch.setenv("NETWATCH_WEBHOOK_URL", "https://hooks.example.test/synthetic")
    monkeypatch.delenv("NETWATCH_SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("NETWATCH_NOTIFY_MIN_SEVERITY", "High")
    notifications._reset_notification_state_for_tests()
    with inventory_store._connect() as conn:
        queued = outbox.enqueue_notification_receipts(
            conn, {"id": 901, "severity": "Critical", "status": "open"}
        )
        assert queued == 1


def test_exhausted_pending_receipt_is_dead_without_delivery(monkeypatch, tmp_path):
    _queued_receipt(monkeypatch, tmp_path)
    with inventory_store._connect() as conn:
        conn.execute(
            "UPDATE notification_deliveries SET attempts = ?, available_at = ?, "
            "claimed_at = '', claim_token = 'old-claim' WHERE alert_id = 901",
            (
                outbox.MAX_DELIVERY_ATTEMPTS,
                outbox._iso(outbox._now() - timedelta(days=1)),
            ),
        )

    def unexpected_delivery(*_args, **_kwargs):
        raise AssertionError("Exhausted receipt must never reach a provider")

    monkeypatch.setattr(outbox, "deliver_stored_notification", unexpected_delivery)
    assert outbox.process_notification_receipts_once() == {
        "claimed": 0,
        "delivered": 0,
        "retry_pending": 0,
        "dead": 0,
    }
    receipt = outbox.notification_delivery_status()["receipts"][0]
    assert receipt["status"] == "dead"
    assert receipt["attempts"] == outbox.MAX_DELIVERY_ATTEMPTS
    assert receipt["last_result"] == "retry_exhausted"
    with inventory_store._connect() as conn:
        row = conn.execute(
            "SELECT claimed_at, claim_token FROM notification_deliveries WHERE alert_id = 901"
        ).fetchone()
    assert row["claimed_at"] == ""
    assert row["claim_token"] == ""


def test_last_allowed_failed_attempt_becomes_dead(monkeypatch, tmp_path):
    _queued_receipt(monkeypatch, tmp_path)
    with inventory_store._connect() as conn:
        conn.execute(
            "UPDATE notification_deliveries SET attempts = ? WHERE alert_id = 901",
            (outbox.MAX_DELIVERY_ATTEMPTS - 1,),
        )
    calls = []

    def failed_delivery(kind, payload):
        calls.append((kind, payload["event_id"]))
        return notifications.ChannelNotificationResult("webhook", "failed", 1)

    monkeypatch.setattr(outbox, "deliver_stored_notification", failed_delivery)
    assert outbox.process_notification_receipts_once() == {
        "claimed": 1,
        "delivered": 0,
        "retry_pending": 0,
        "dead": 1,
    }
    receipt = outbox.notification_delivery_status()["receipts"][0]
    assert receipt["status"] == "dead"
    assert receipt["attempts"] == outbox.MAX_DELIVERY_ATTEMPTS
    assert receipt["last_result"] == "failed"
    assert len(calls) == 1
    assert outbox.process_notification_receipts_once()["claimed"] == 0
