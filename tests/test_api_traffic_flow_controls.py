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


def _capture_result() -> dict[str, object]:
    return {
        "interface": "eth0",
        "duration_seconds": 1,
        "captured_packets": 4,
        "captured_bytes": 1900,
        "payload_retained": False,
        "flows": [
            {
                "flow_id": "flow-https",
                "protocol": "TCP",
                "service": "https",
                "tcp_state": "established",
                "originator": {"ip": "10.0.0.10", "port": 51000},
                "responder": {"ip": "10.0.0.20", "port": 443},
                "packets": 3,
                "bytes": 1600,
                "originator_packets": 2,
                "originator_bytes": 1000,
                "responder_packets": 1,
                "responder_bytes": 600,
                "duration_ms": 50,
            },
            {
                "flow_id": "flow-dns",
                "protocol": "UDP",
                "service": "dns",
                "originator": {"ip": "10.0.0.10", "port": 53000},
                "responder": {"ip": "10.0.0.53", "port": 53},
                "packets": 1,
                "bytes": 300,
                "originator_packets": 1,
                "originator_bytes": 100,
                "responder_packets": 0,
                "responder_bytes": 200,
                "duration_ms": 10,
            },
        ],
        "flow_count": 2,
        "conversations": [{"legacy": True}],
    }


def test_live_capture_applies_nested_flow_controls_and_rejects_invalid_filters(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(api, "capture_traffic", lambda **_: _capture_result())

    with _client(monkeypatch, tmp_path) as client:
        filtered = client.post(
            "/api/traffic/capture",
            headers=API_HEADERS,
            json={
                "interface": "eth0",
                "duration_seconds": 1,
                "max_packets": 10,
                "authorized": True,
                "flow_controls": {
                    "display_filter": "protocol == tcp and bytes >= 1000",
                    "service": "https",
                    "sort_by": "bytes",
                    "limit": 10,
                },
            },
        )
        invalid = client.post(
            "/api/traffic/capture",
            headers=API_HEADERS,
            json={
                "interface": "eth0",
                "authorized": True,
                "flow_controls": {"display_filter": "payload == secret"},
            },
        )

    assert filtered.status_code == 200
    assert filtered.json()["flow_count"] == 1
    assert filtered.json()["flows"][0]["flow_id"] == "flow-https"
    assert filtered.json()["conversation_count"] == 1
    assert filtered.json()["flow_analysis"]["applied"] is True
    assert filtered.json()["flow_analysis"]["display_filter"] == "protocol == tcp and bytes >= 1000"
    assert invalid.status_code == 400
    assert "Unsupported field" in invalid.json()["detail"]
