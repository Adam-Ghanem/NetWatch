from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import backend.main as api
import inventory_store
import notifications
import operations_store

ADMIN_KEY = "notification-admin-key-with-at-least-32-characters"
OPERATOR_KEY = "notification-operator-key-with-at-least-32-characters"
VIEWER_KEY = "notification-viewer-key-with-at-least-32-characters"
AUDIT_KEY = "notification-audit-key-with-at-least-32-characters"


class _FakeResponse:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def getcode(self) -> int:
        return self.status

    def read(self, _: int) -> bytes:
        return b"ok"


def _configure_webhook(monkeypatch) -> None:
    monkeypatch.setenv("NETWATCH_WEBHOOK_URL", "https://hooks.example.test/netwatch-secret")
    monkeypatch.delenv("NETWATCH_SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("NETWATCH_NOTIFY_MIN_SEVERITY", "High")
    monkeypatch.setenv("NETWATCH_NOTIFY_INCLUDE_RAW_TARGETS", "false")
    notifications._reset_notification_state_for_tests()


def _alert() -> dict:
    return {
        "id": 42,
        "severity": "High",
        "status": "open",
        "category": "asset_not_observed",
        "target": "server.internal (192.168.10.25)",
        "details": "Raw hostname db.internal must remain private.",
        "occurrence_count": 2,
        "overdue": False,
        "_notification_event": "alert_created",
    }


@pytest.mark.parametrize(
    "candidate",
    [
        "http://hooks.example.test/netwatch",
        "ftp://hooks.example.test/netwatch",
        "https://user:password@hooks.example.test/netwatch",
        "https://hooks.example.test/netwatch?token=secret",
        "https://hooks.example.test/netwatch#secret",
        "hooks.example.test/netwatch",
    ],
)
def test_notification_url_validation_rejects_unsafe_urls(candidate):
    with pytest.raises(notifications.NotificationConfigurationError):
        notifications.validate_notification_url(candidate)


def test_redirect_responses_are_not_followed(monkeypatch):
    _configure_webhook(monkeypatch)
    calls = 0

    def redirect_response(request, timeout):
        nonlocal calls
        calls += 1
        assert timeout == notifications.NOTIFICATION_TIMEOUT_SECONDS
        raise urllib.error.HTTPError(
            request.full_url,
            302,
            "Found",
            {},
            io.BytesIO(b"redirect blocked"),
        )

    monkeypatch.setattr(notifications, "_open_without_redirects", redirect_response)
    result = notifications.send_alert_notification(_alert())
    handler = notifications._NoRedirectHandler()

    assert calls == 1
    assert result.failed == 1
    assert (
        handler.redirect_request(
            urllib.request.Request("https://hooks.example.test/original"),
            io.BytesIO(),
            302,
            "Found",
            {},
            "https://redirect.example.test/target",
        )
        is None
    )


def test_payload_is_deidentified_until_raw_target_is_explicitly_enabled(monkeypatch):
    _configure_webhook(monkeypatch)
    captured: list[dict] = []

    def capture(request, timeout):
        assert timeout == 5
        captured.append(json.loads(bytes(request.data or b"{}").decode("utf-8")))
        return _FakeResponse()

    monkeypatch.setattr(notifications, "_open_without_redirects", capture)
    first = notifications.send_alert_notification(_alert())
    encoded = json.dumps(captured[-1], sort_keys=True)

    assert first.delivered == 1
    assert "192.168.10.25" not in encoded
    assert "server.internal" not in encoded
    assert "db.internal" not in encoded
    assert captured[-1]["privacy"]["deidentified"] is True

    notifications._reset_notification_state_for_tests()
    monkeypatch.setenv("NETWATCH_NOTIFY_INCLUDE_RAW_TARGETS", "true")
    second = notifications.send_alert_notification(_alert())
    encoded = json.dumps(captured[-1], sort_keys=True)

    assert second.delivered == 1
    assert "192.168.10.25" in encoded
    assert "server.internal" in encoded
    assert "db.internal" not in encoded
    assert captured[-1]["privacy"]["raw_target_included"] is True


def test_debounce_suppresses_duplicate_alert_notifications(monkeypatch):
    _configure_webhook(monkeypatch)
    calls = 0

    def capture(*_, **__):
        nonlocal calls
        calls += 1
        return _FakeResponse()

    monkeypatch.setattr(notifications, "_open_without_redirects", capture)

    first = notifications.send_alert_notification(_alert())
    second = notifications.send_alert_notification(_alert())

    assert first.delivered == 1
    assert second.reason == "debounced"
    assert second.attempted == 0
    assert calls == 1


def test_retries_use_bounded_exponential_backoff(monkeypatch):
    _configure_webhook(monkeypatch)
    delays: list[float] = []

    def unavailable(*_, **__):
        raise urllib.error.URLError("unavailable")

    monkeypatch.setattr(notifications, "_open_without_redirects", unavailable)
    monkeypatch.setattr(notifications.time, "sleep", delays.append)

    result = notifications.send_alert_notification(_alert())

    assert result.channels[0].attempts == notifications.NOTIFICATION_MAX_RETRIES + 1
    assert delays == [0.25, 0.5, 1.0]


def test_circuit_breaker_stops_hammering_failed_channel(monkeypatch):
    _configure_webhook(monkeypatch)
    monkeypatch.setattr(notifications, "NOTIFICATION_MAX_RETRIES", 0)
    calls = 0

    def unavailable(*_, **__):
        nonlocal calls
        calls += 1
        raise urllib.error.URLError("unavailable")

    monkeypatch.setattr(notifications, "_open_without_redirects", unavailable)
    for alert_id in range(notifications.NOTIFICATION_CIRCUIT_FAILURE_THRESHOLD):
        alert = {**_alert(), "id": 1_000 + alert_id}
        assert notifications.send_alert_notification(alert).failed == 1

    blocked = notifications.send_alert_notification({**_alert(), "id": 2_000})

    assert calls == notifications.NOTIFICATION_CIRCUIT_FAILURE_THRESHOLD
    assert blocked.reason == "circuit_open"
    assert blocked.attempted == 0


def test_failing_webhook_does_not_block_alert_creation(monkeypatch, tmp_path):
    _configure_webhook(monkeypatch)
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    monkeypatch.setattr(notifications.time, "sleep", lambda _: None)
    attempts = 0
    delivery_started = threading.Event()
    release_delivery = threading.Event()

    def unavailable(*_, **__):
        nonlocal attempts
        attempts += 1
        delivery_started.set()
        release_delivery.wait(timeout=2)
        raise urllib.error.URLError("unavailable")

    monkeypatch.setattr(notifications, "_open_without_redirects", unavailable)
    initial = inventory_store.record_network_scan(
        "192.168.60.0/30",
        [{"IP Address": "192.168.60.1", "Status": "Online"}],
    )
    operations_store.create_alerts_for_changes(initial)
    inventory_store.update_asset_context(
        "192.168.60.1",
        owner="Network Operations",
        department="IT",
        location="HQ",
        criticality="Critical",
        notes="Core service",
        actor_role="admin",
    )
    missing = inventory_store.record_network_scan("192.168.60.0/30", [])
    summaries = []
    errors: list[Exception] = []
    creation_finished = threading.Event()

    def create_alert() -> None:
        try:
            summaries.append(operations_store.create_alerts_for_changes(missing))
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)
        finally:
            creation_finished.set()

    creation_thread = threading.Thread(target=create_alert)
    creation_thread.start()
    try:
        assert delivery_started.wait(timeout=1)
        assert creation_finished.wait(timeout=1)
    finally:
        release_delivery.set()
        creation_thread.join(timeout=2)
    notifications._wait_for_notification_queue_for_tests()
    saved = operations_store.recent_alerts(severity="Critical")

    assert errors == []
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.created == 1
    assert len(saved) == 1
    assert saved[0]["target"] == "192.168.60.1"
    assert attempts == notifications.NOTIFICATION_MAX_RETRIES + 1


def test_sla_breach_is_notified_once_per_transition(monkeypatch, tmp_path):
    _configure_webhook(monkeypatch)
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    payloads: list[dict] = []

    def capture(request, timeout):
        payloads.append(json.loads(bytes(request.data or b"{}").decode("utf-8")))
        return _FakeResponse()

    monkeypatch.setattr(notifications, "_open_without_redirects", capture)
    initial = inventory_store.record_network_scan(
        "192.168.70.0/30",
        [{"IP Address": "192.168.70.1", "Status": "Online"}],
    )
    operations_store.create_alerts_for_changes(initial)
    inventory_store.update_asset_context(
        "192.168.70.1",
        owner="Operations",
        department="IT",
        location="HQ",
        criticality="High",
        notes="Service",
        actor_role="admin",
    )
    missing = inventory_store.record_network_scan("192.168.70.0/30", [])
    operations_store.create_alerts_for_changes(missing)
    notifications._wait_for_notification_queue_for_tests()
    notifications._reset_notification_state_for_tests()
    operations_store._sla_notified_alert_ids.clear()
    payloads.clear()
    with inventory_store._connect() as conn:
        conn.execute(
            "UPDATE operation_alerts SET due_at = ? WHERE severity = 'High'",
            ("2026-01-01T00:00:00+00:00",),
        )

    first = operations_store.notify_overdue_alert_transitions(now="2026-01-02T00:00:00+00:00")
    second = operations_store.notify_overdue_alert_transitions(now="2026-01-02T00:01:00+00:00")

    assert first == 1
    assert second == 0
    assert [payload["event"] for payload in payloads] == ["sla_breached"]


def _api_client(monkeypatch, tmp_path: Path) -> TestClient:
    monkeypatch.setenv("NETWATCH_API_KEY", ADMIN_KEY)
    monkeypatch.setenv("NETWATCH_OPERATOR_KEY", OPERATOR_KEY)
    monkeypatch.setenv("NETWATCH_VIEWER_KEY", VIEWER_KEY)
    monkeypatch.setenv("NETWATCH_AUDIT_HMAC_KEY", AUDIT_KEY)
    monkeypatch.setenv("NETWATCH_OIDC_ENABLED", "false")
    monkeypatch.delenv("NETWATCH_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("NETWATCH_SLACK_WEBHOOK_URL", raising=False)
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    api._rate_events.clear()
    return TestClient(api.app, base_url="http://127.0.0.1")


def test_notification_endpoints_require_admin_access(monkeypatch, tmp_path):
    with _api_client(monkeypatch, tmp_path) as client:
        operator = client.post(
            "/api/notifications/test",
            headers={"X-NetWatch-Key": OPERATOR_KEY},
        )
        viewer = client.get(
            "/api/notifications/status",
            headers={"X-NetWatch-Key": VIEWER_KEY},
        )

    assert operator.status_code == 403
    assert viewer.status_code == 403


def test_notification_status_never_returns_configured_urls(monkeypatch, tmp_path):
    with _api_client(monkeypatch, tmp_path) as client:
        monkeypatch.setenv("NETWATCH_WEBHOOK_URL", "https://hooks.example.test/super-secret-path")
        response = client.get(
            "/api/notifications/status",
            headers={"X-NetWatch-Key": ADMIN_KEY},
        )

    assert response.status_code == 200
    assert response.json()["channels"][0] == {"kind": "webhook", "enabled": True}
    assert "hooks.example.test" not in response.text
    assert "super-secret-path" not in response.text
