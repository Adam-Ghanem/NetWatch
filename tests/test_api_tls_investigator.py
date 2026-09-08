from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as api
import inventory_store

TEST_API_KEY = "test-secret-with-at-least-32-characters"
AUDIT_HMAC_KEY = "test-independent-audit-hmac-key-with-enough-characters"
API_HEADERS = {"X-NetWatch-Key": TEST_API_KEY}


def _client(monkeypatch, tmp_path: Path) -> TestClient:
    monkeypatch.delenv("NETWATCH_OPERATOR_KEY", raising=False)
    monkeypatch.delenv("NETWATCH_VIEWER_KEY", raising=False)
    monkeypatch.setenv("NETWATCH_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("NETWATCH_AUDIT_HMAC_KEY", AUDIT_HMAC_KEY)
    monkeypatch.setenv("NETWATCH_OIDC_ENABLED", "false")
    api._rate_events.clear()
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    return TestClient(api.app, base_url="http://127.0.0.1")


def test_tls_investigator_requires_authentication(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/assets/192.0.2.10/tls/investigator")

    assert response.status_code == 401


def test_tls_investigator_validates_target_and_returns_bounded_evidence(monkeypatch, tmp_path):
    history = [
        {
            "scan_run_id": 8,
            "ip_address": "192.0.2.10",
            "port": 443,
            "protocol": "TCP",
            "observed_at": "2026-09-08T00:00:00+00:00",
            "tls_protocol": "TLSv1.3",
            "tls_cipher": "TLS_AES_256_GCM_SHA384",
            "tls_alpn": "h2",
            "certificate_sha256": "a" * 64,
            "certificate_not_before": "2026-08-01T00:00:00+00:00",
            "certificate_not_after": "2026-09-20T00:00:00+00:00",
            "certificate_status": "Valid",
            "certificate_days_remaining": 12,
        }
    ]
    changes = [
        {
            "scan_run_id": 8,
            "ip_address": "192.0.2.10",
            "port": 443,
            "protocol": "TCP",
            "observed_at": "2026-09-08T00:00:00+00:00",
            "change_type": "certificate_expiry_risk",
            "severity": "medium",
            "summary": "TLS certificate entered the 30-day expiry warning window.",
            "previous": "42",
            "current": "12",
            "alert_recommended": True,
            "alert_severity": "medium",
            "alert_reason": "TLS certificate entered the 30-day expiry warning window.",
        }
    ]
    calls: dict[str, object] = {}

    def fake_history(*, limit: int, ip_address: str):
        calls["history"] = (limit, ip_address)
        return history

    def fake_changes(
        *,
        limit: int,
        ip_address: str,
        expiry_warning_days: int,
        alert_min_severity: str,
    ):
        calls["changes"] = (limit, ip_address, expiry_warning_days, alert_min_severity)
        return changes

    monkeypatch.setattr(api, "recent_tls_service_history", fake_history, raising=False)
    monkeypatch.setattr(api, "recent_tls_service_changes", fake_changes, raising=False)

    with _client(monkeypatch, tmp_path) as client:
        invalid = client.get(
            "/api/assets/not-an-ip/tls/investigator",
            headers=API_HEADERS,
        )
        response = client.get(
            "/api/assets/192.0.2.10/tls/investigator",
            headers=API_HEADERS,
            params={
                "history_limit": 25,
                "change_limit": 15,
                "expiry_warning_days": 45,
                "alert_min_severity": "high",
            },
        )

    assert invalid.status_code == 400
    assert response.status_code == 200
    body = response.json()
    assert body["target"] == "192.0.2.10"
    assert body["history_count"] == 1
    assert body["change_count"] == 1
    assert body["recommended_alert_count"] == 1
    assert body["history"] == history
    assert body["changes"] == changes
    assert calls["history"] == (25, "192.0.2.10")
    assert calls["changes"] == (15, "192.0.2.10", 45, "high")


def test_tls_investigator_rejects_invalid_severity_threshold(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get(
            "/api/assets/192.0.2.10/tls/investigator",
            headers=API_HEADERS,
            params={"alert_min_severity": "urgent"},
        )

    assert response.status_code == 422
