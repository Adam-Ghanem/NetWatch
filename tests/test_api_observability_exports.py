from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as api
import inventory_store

TEST_API_KEY = "test-secret-with-at-least-32-characters"
AUDIT_HMAC_KEY = "test-independent-audit-hmac-key-with-enough-characters"
API_HEADERS = {"X-NetWatch-Key": TEST_API_KEY}
OFFLINE_HEADERS = {
    "X-NetWatch-Key": TEST_API_KEY,
    "Content-Type": "application/octet-stream",
}


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
        "source": "pcap",
        "captured_packets": 3,
        "captured_bytes": 1600,
        "payload_retained": False,
        "flows": [
            {
                "flow_id": "flow-app",
                "community_id": "1:example-community-id",
                "protocol": "TCP",
                "service": "https",
                "tcp_state": "established",
                "originator": {"ip": "10.0.0.10", "port": 51000},
                "responder": {"ip": "10.0.0.20", "port": 443},
                "packets": 3,
                "bytes": 1600,
                "originator_packets": 2,
                "originator_bytes": 900,
                "responder_packets": 1,
                "responder_bytes": 700,
                "duration_ms": 75,
                "protocol_event_count": 3,
                "protocol_events": [
                    {"event_type": "dns", "query": "private.example"},
                    {"event_type": "tls", "server_name": "secret.example"},
                    {"event_type": "http", "host": "internal.example", "path": "/admin"},
                ],
                "payload": "must-not-export",
                "authorization": "Bearer must-not-export",
            }
        ],
        "flow_count": 1,
        "conversations": [],
    }


def _live_request() -> dict[str, object]:
    return {
        "interface": "eth0",
        "duration_seconds": 1,
        "max_packets": 10,
        "authorized": True,
        "flow_controls": {"service": "https", "limit": 10},
    }


def test_live_observability_json_is_authenticated_bounded_and_privacy_first(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(api, "capture_traffic", lambda **_: _capture_result())

    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/traffic/capture/observability.json",
            headers=API_HEADERS,
            json=_live_request(),
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == (
        'attachment; filename="netwatch-observability.json"'
    )
    body = response.json()
    assert body["schema"] == "netwatch.flow.v1"
    assert body["count"] == 1
    assert body["payload_retained"] is False
    attributes = body["records"][0]["attributes"]
    assert attributes["network.community_id"] == "1:example-community-id"
    assert attributes["netwatch.flow.protocol_event_count"] == 3
    assert attributes["netwatch.flow.protocol_event_types"] == ["dns", "tls", "http"]
    serialized = response.text.lower()
    for forbidden in (
        "private.example",
        "secret.example",
        "internal.example",
        "/admin",
        "must-not-export",
        "authorization",
    ):
        assert forbidden not in serialized


def test_offline_observability_ndjson_requires_authorization_and_exposes_safe_records(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(api, "analyze_capture_bytes", lambda *_, **__: _capture_result())

    with _client(monkeypatch, tmp_path) as client:
        denied = client.post(
            "/api/traffic/offline/observability.ndjson",
            headers=OFFLINE_HEADERS,
            content=b"pcap",
        )
        response = client.post(
            "/api/traffic/offline/observability.ndjson",
            headers=OFFLINE_HEADERS,
            params={"authorized": "true", "packet_limit": 10, "flow_limit": 1},
            content=b"pcap",
        )

    assert denied.status_code == 403
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"] == (
        'attachment; filename="netwatch-offline-observability.ndjson"'
    )
    records = [json.loads(line) for line in response.text.splitlines() if line]
    assert len(records) == 1
    assert records[0]["schema"] == "netwatch.flow.v1"
    attributes = records[0]["attributes"]
    assert attributes["network.community_id"] == "1:example-community-id"
    assert attributes["netwatch.flow.protocol_event_types"] == ["dns", "tls", "http"]
    assert "private.example" not in response.text
    assert "secret.example" not in response.text
    assert "internal.example" not in response.text
