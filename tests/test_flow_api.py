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


def test_traffic_capture_applies_bounded_flow_query_filters(monkeypatch, tmp_path):
    def fake_capture(**_):
        return {
            "interface": "eth0",
            "duration_seconds": 2,
            "captured_packets": 4,
            "captured_bytes": 540,
            "payload_retained": False,
            "filter": {"protocol": "all", "ip_address": "", "port": None},
            "protocols": [],
            "conversations": [],
            "devices": [],
            "packets": [],
            "flows": [
                {
                    "flow_id": "https-flow",
                    "originator": {"ip": "192.168.1.10", "port": 51000},
                    "responder": {"ip": "192.168.1.1", "port": 443},
                    "protocol": "tcp",
                    "service": "https",
                    "tcp_state": "established",
                    "packets": 3,
                    "bytes": 500,
                    "duration_ms": 50,
                    "last_seen": "2026-08-31T20:00:00Z",
                },
                {
                    "flow_id": "dns-flow",
                    "originator": {"ip": "192.168.1.10", "port": 53000},
                    "responder": {"ip": "192.168.1.53", "port": 53},
                    "protocol": "udp",
                    "service": "dns",
                    "tcp_state": "",
                    "packets": 1,
                    "bytes": 40,
                    "duration_ms": 5,
                    "last_seen": "2026-08-31T20:00:01Z",
                },
            ],
            "flow_count": 2,
            "visibility_note": "host traffic only",
        }

    monkeypatch.setattr(api, "capture_traffic", fake_capture)
    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/traffic/capture",
            headers=API_HEADERS,
            json={
                "interface": "eth0",
                "authorized": True,
                "flow_service": "https",
                "flow_min_bytes": 100,
                "flow_sort_by": "bytes",
                "flow_limit": 10,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["flow_total_count"] == 2
    assert body["flow_count"] == 1
    assert [flow["flow_id"] for flow in body["flows"]] == ["https-flow"]
    assert body["flow_query"] == {
        "ip_address": "",
        "protocol": "",
        "service": "https",
        "state": "",
        "min_bytes": 100,
        "sort_by": "bytes",
        "limit": 10,
    }


def test_traffic_capture_rejects_invalid_flow_query_bounds_before_capture(monkeypatch, tmp_path):
    capture_called = False

    def fake_capture(**_):
        nonlocal capture_called
        capture_called = True
        return {}

    monkeypatch.setattr(api, "capture_traffic", fake_capture)
    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/traffic/capture",
            headers=API_HEADERS,
            json={
                "interface": "eth0",
                "authorized": True,
                "flow_limit": 1001,
            },
        )

    assert response.status_code == 422
    assert capture_called is False
