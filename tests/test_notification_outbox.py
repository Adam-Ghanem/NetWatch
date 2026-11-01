from __future__ import annotations

import json
import sqlite3

from fastapi.testclient import TestClient

import backend.main as api
import inventory_store
import notification_outbox as outbox
import notifications
import operations_store


def _db(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    inventory_store.init_db()


def _enabled(monkeypatch):
    monkeypatch.setenv("NETWATCH_DURABLE_NOTIFICATIONS_ENABLED", "true")
    monkeypatch.setenv("NETWATCH_WEBHOOK_URL", "https://hooks.example.test/private-token")
    monkeypatch.delenv("NETWATCH_SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("NETWATCH_NOTIFY_MIN_SEVERITY", "High")
    monkeypatch.setenv("NETWATCH_NOTIFY_INCLUDE_RAW_TARGETS", "false")
    notifications._reset_notification_state_for_tests()


def _alert(alert_id=42, severity="Critical"):
    return {
        "id": alert_id, "severity": severity, "status": "open",
        "category": "asset_not_observed", "target": "secret.internal (10.0.0.5)",
        "occurrence_count": 1,
    }


def test_queue_is_idempotent_and_stores_no_urls_or_raw_targets(monkeypatch, tmp_path):
    _db(monkeypatch, tmp_path)
    _enabled(monkeypatch)
    with inventory_store._connect() as conn:
        assert outbox.enqueue_notification_receipts(conn, _alert()) == 1
        assert outbox.enqueue_notification_receipts(conn, _alert()) == 0
        content = conn.execute(
            "SELECT payload FROM notification_deliveries"
        ).fetchone()[0]
    assert "secret.internal" not in content
    assert "10.0.0.5" not in content
    assert "private-token" not in content
    assert json.loads(content)["event_id"]


def test_delivery_recovers_after_restart_and_records_receipt(monkeypatch, tmp_path):
    _db(monkeypatch, tmp_path)
    _enabled(monkeypatch)
    with inventory_store._connect() as conn:
        outbox.enqueue_notification_receipts(conn, _alert())
    sent = []

    def mock_delivery(kind, payload):
        sent.append((kind, payload))
        return notifications.ChannelNotificationResult("webhook", "delivered", 1)

    monkeypatch.setattr(outbox, "deliver_stored_notification", mock_delivery)
    assert outbox.process_notification_receipts_once()["delivered"] == 1
    assert outbox.process_notification_receipts_once()["claimed"] == 0
    status = outbox.notification_delivery_status()
    assert status["counts"]["delivered"] == 1
    assert status["receipts"][0]["attempts"] == 1
    assert sent[0][1]["event_id"] == status["receipts"][0]["event_id"]


def test_transient_failure_is_delayed_and_does_not_hammer(monkeypatch, tmp_path):
    _db(monkeypatch, tmp_path)
    _enabled(monkeypatch)
    with inventory_store._connect() as conn:
        outbox.enqueue_notification_receipts(conn, _alert())
    monkeypatch.setattr(
        outbox, "deliver_stored_notification",
        lambda kind, payload: notifications.ChannelNotificationResult("webhook", "failed", 1),
    )
    assert outbox.process_notification_receipts_once()["retry_pending"] == 1
    assert outbox.process_notification_receipts_once()["claimed"] == 0
    assert outbox.notification_delivery_status()["receipts"][0]["last_result"] == "failed"


def test_deferred_disabled_channel_does_not_consume_retry_budget(monkeypatch, tmp_path):
    _db(monkeypatch, tmp_path)
    _enabled(monkeypatch)
    with inventory_store._connect() as conn:
        outbox.enqueue_notification_receipts(conn, _alert())
    monkeypatch.setattr(
        outbox, "deliver_stored_notification",
        lambda kind, payload: notifications.ChannelNotificationResult("webhook", "disabled"),
    )
    assert outbox.process_notification_receipts_once()["retry_pending"] == 1
    assert outbox.notification_delivery_status()["receipts"][0]["attempts"] == 0


def test_threshold_and_unconfigured_channel_do_not_queue(monkeypatch, tmp_path):
    _db(monkeypatch, tmp_path)
    _enabled(monkeypatch)
    with inventory_store._connect() as conn:
        assert outbox.enqueue_notification_receipts(conn, _alert(severity="Low")) == 0
        monkeypatch.delenv("NETWATCH_WEBHOOK_URL")
        assert outbox.enqueue_notification_receipts(conn, _alert()) == 0


def test_case_creation_is_atomic_and_does_not_enqueue_in_memory(monkeypatch, tmp_path):
    _db(monkeypatch, tmp_path)
    _enabled(monkeypatch)
    queued = []
    monkeypatch.setattr(operations_store, "enqueue_alert_notification", queued.append)
    inventory_store.record_network_scan(
        "192.168.61.0/30", [{"IP Address": "192.168.61.1", "Status": "Online"}]
    )
    inventory_store.update_asset_context(
        "192.168.61.1", criticality="Critical", actor_role="admin"
    )
    missing = inventory_store.record_network_scan("192.168.61.0/30", [])
    summary = operations_store.create_alerts_for_changes(missing)
    assert summary.created == 1
    assert queued == []
    assert outbox.notification_delivery_status()["counts"]["pending"] == 1


def test_admin_status_has_no_raw_payloads_and_viewer_is_denied(monkeypatch, tmp_path):
    _db(monkeypatch, tmp_path)
    _enabled(monkeypatch)
    monkeypatch.setenv("NETWATCH_API_KEY", "admin-outbox-key-with-at-least-32-characters")
    monkeypatch.setenv("NETWATCH_VIEWER_KEY", "viewer-outbox-key-with-at-least-32-characters")
    monkeypatch.setenv("NETWATCH_AUDIT_HMAC_KEY", "independent-audit-key-with-at-least-32-characters")
    monkeypatch.setenv("NETWATCH_OIDC_ENABLED", "false")
    with inventory_store._connect() as conn:
        outbox.enqueue_notification_receipts(conn, _alert())
    with TestClient(api.app, base_url="http://127.0.0.1") as client:
        viewer = client.get(
            "/api/notifications/status",
            headers={"X-NetWatch-Key": "viewer-outbox-key-with-at-least-32-characters"},
        )
        admin = client.get(
            "/api/notifications/status",
            headers={"X-NetWatch-Key": "admin-outbox-key-with-at-least-32-characters"},
        )
    assert viewer.status_code == 403
    assert admin.status_code == 200
    assert admin.json()["durable_alert_created_enabled"] is True
    assert admin.json()["delivery"]["counts"]["pending"] == 1
    assert "private-token" not in admin.text
    assert "10.0.0.5" not in admin.text
