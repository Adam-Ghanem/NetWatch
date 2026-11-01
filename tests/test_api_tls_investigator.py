from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as api
import inventory_store

VIEWER_API_KEY = "viewer-secret-with-at-least-32-characters"
AUDIT_HMAC_KEY = "test-independent-audit-hmac-key-with-enough-characters"
VIEWER_HEADERS = {"X-NetWatch-Key": VIEWER_API_KEY}


def _client(monkeypatch, tmp_path: Path) -> TestClient:
    monkeypatch.delenv("NETWATCH_API_KEY", raising=False)
    monkeypatch.delenv("NETWATCH_OPERATOR_KEY", raising=False)
    monkeypatch.setenv("NETWATCH_VIEWER_KEY", VIEWER_API_KEY)
    monkeypatch.setenv("NETWATCH_AUDIT_HMAC_KEY", AUDIT_HMAC_KEY)
    monkeypatch.setenv("NETWATCH_OIDC_ENABLED", "false")
    api._rate_events.clear()
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    return TestClient(api.app, base_url="http://127.0.0.1")


def test_tls_investigator_requires_authentication(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/tls/investigator")

    assert response.status_code == 401


def test_viewer_can_read_bounded_tls_investigator_snapshot(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get(
            "/api/tls/investigator",
            headers=VIEWER_HEADERS,
            params={
                "history_limit": 1000,
                "limit": 1000,
                "ip_address": "2001:db8::20",
                "port": 443,
                "protocol": "tcp",
                "change_type": "tls_protocol_downgrade",
                "severity": "high",
                "alerts_only": "true",
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["history_count"] == 0
    assert payload["service_count"] == 0
    assert payload["change_count"] == 0
    assert payload["alert_recommended_count"] == 0
    assert payload["timeline"] == []
    assert payload["items"] == []
    assert payload["evidence_scope"] == {
        "source": "retained_tls_service_metadata",
        "network_probes_added": False,
        "certificate_bodies_retained": False,
        "certificate_identity_fields_retained": False,
    }


def test_tls_investigator_query_bounds_are_enforced(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        invalid_port = client.get(
            "/api/tls/investigator",
            headers=VIEWER_HEADERS,
            params={"port": 0},
        )
        invalid_history_limit = client.get(
            "/api/tls/investigator",
            headers=VIEWER_HEADERS,
            params={"history_limit": 1001},
        )
        invalid_limit = client.get(
            "/api/tls/investigator",
            headers=VIEWER_HEADERS,
            params={"limit": 1001},
        )

    assert invalid_port.status_code == 422
    assert invalid_history_limit.status_code == 422
    assert invalid_limit.status_code == 422


def test_tls_export_requires_authentication_and_rejects_invalid_bounds(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        missing_key = client.get("/api/tls/investigator/export.csv")
        invalid_limit = client.get(
            "/api/tls/investigator/export.csv",
            headers=VIEWER_HEADERS,
            params={"limit": 1001},
        )
        invalid_format = client.get("/api/tls/investigator/export.xml", headers=VIEWER_HEADERS)
    assert missing_key.status_code == 401
    assert invalid_limit.status_code == 422
    assert invalid_format.status_code == 422


def test_viewer_exports_same_filtered_retained_tls_evidence(monkeypatch, tmp_path):
    captured = []

    def fake_snapshot(**kwargs):
        captured.append(kwargs)
        return {
            "items": [
                {
                    "scan_run_id": 9,
                    "observed_at": "2026-11-01T14:00:00+00:00",
                    "ip_address": "2001:db8::5",
                    "port": 443,
                    "protocol": "TCP",
                    "change_type": "tls_protocol_downgrade",
                    "severity": "high",
                    "summary": "Confirmed downgrade",
                    "previous": "TLSv1.3",
                    "current": "TLSv1.2",
                    "alert_recommended": True,
                    "certificate_body": "never-export-this",
                }
            ]
        }

    monkeypatch.setattr(api, "recent_tls_investigator_snapshot", fake_snapshot)
    query = {
        "history_limit": 20,
        "limit": 10,
        "ip_address": "2001:db8::5",
        "port": 443,
        "protocol": "tcp",
        "change_type": "tls_protocol_downgrade",
        "severity": "high",
        "alerts_only": "true",
    }
    with _client(monkeypatch, tmp_path) as client:
        results = {
            kind: client.get(
                f"/api/tls/investigator/export.{kind}",
                params=query,
                headers=VIEWER_HEADERS,
            )
            for kind in ("csv", "json", "ndjson")
        }

    assert all(result.status_code == 200 for result in results.values())
    assert len(captured) == 3
    assert all(call["ip_address"] == "2001:db8::5" for call in captured)
    assert all(call["alerts_only"] is True for call in captured)
    assert all(call["port"] == 443 and call["limit"] == 10 for call in captured)
    assert results["csv"].headers["content-type"].startswith("text/csv")
    assert results["json"].json()["count"] == 1
    assert results["json"].json()["events"][0]["severity"] == "high"
    assert len(results["ndjson"].text.splitlines()) == 1
    for response in results.values():
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert "attachment; filename=" in response.headers["content-disposition"]
        assert "never-export-this" not in response.text
