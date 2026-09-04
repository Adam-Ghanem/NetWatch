from __future__ import annotations

import json
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
        "captured_packets": 2,
        "captured_bytes": 1200,
        "payload_retained": False,
        "flows": [
            {
                "flow_id": "flow-https",
                "community_id": "1:9j2Dzwrw7T9E+IZi4b4IVT66HBI=",
                "protocol": "TCP",
                "service": "https",
                "tcp_state": "established",
                "originator": {"ip": "10.0.0.10", "port": 51000},
                "responder": {"ip": "10.0.0.20", "port": 443},
                "packets": 2,
                "bytes": 1200,
                "originator_packets": 1,
                "originator_bytes": 700,
                "responder_packets": 1,
                "responder_bytes": 500,
                "duration_ms": 50,
                "payload": "must-not-export",
                "raw": "must-not-export",
            }
        ],
        "flow_count": 1,
        "conversations": [],
    }


def _request_body() -> dict[str, object]:
    return {
        "interface": "eth0",
        "duration_seconds": 1,
        "max_packets": 10,
        "authorized": True,
        "flow_controls": {"service": "https", "limit": 10},
    }


def test_json_download_is_authenticated_and_metadata_only(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "capture_traffic", lambda **_: _capture_result())

    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/traffic/capture/export.json",
            headers=API_HEADERS,
            json=_request_body(),
        )

    disposition = 'attachment; filename="netwatch-flows.json"'
    payload = response.json()
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"] == disposition
    assert payload["count"] == 1
    assert payload["payload_retained"] is False
    assert payload["flows"][0]["community_id"] == "1:9j2Dzwrw7T9E+IZi4b4IVT66HBI="
    assert "payload" not in payload["flows"][0]
    assert "raw" not in payload["flows"][0]


def test_csv_and_ndjson_downloads_have_attachment_headers(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "capture_traffic", lambda **_: _capture_result())

    with _client(monkeypatch, tmp_path) as client:
        csv_response = client.post(
            "/api/traffic/capture/export.csv",
            headers=API_HEADERS,
            json=_request_body(),
        )
        ndjson_response = client.post(
            "/api/traffic/capture/export.ndjson",
            headers=API_HEADERS,
            json=_request_body(),
        )

    csv_disposition = 'attachment; filename="netwatch-flows.csv"'
    ndjson_disposition = 'attachment; filename="netwatch-flows.ndjson"'
    assert csv_response.status_code == 200
    assert csv_response.headers["content-type"].startswith("text/csv")
    assert csv_response.headers["content-disposition"] == csv_disposition
    assert "community_id" in csv_response.text.splitlines()[0]
    assert "must-not-export" not in csv_response.text

    assert ndjson_response.status_code == 200
    assert ndjson_response.headers["content-type"].startswith("application/x-ndjson")
    assert ndjson_response.headers["content-disposition"] == ndjson_disposition
    record = json.loads(ndjson_response.text.strip())
    assert record["event_type"] == "flow"
    assert record["payload_retained"] is False
    assert record["community_id"] == "1:9j2Dzwrw7T9E+IZi4b4IVT66HBI="
    assert "payload" not in record
    assert "raw" not in record


def test_download_rejects_missing_authorization_and_invalid_filter(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "capture_traffic", lambda **_: _capture_result())

    with _client(monkeypatch, tmp_path) as client:
        unauthorized = client.post(
            "/api/traffic/capture/export.json",
            headers=API_HEADERS,
            json={"interface": "eth0", "authorized": False},
        )
        invalid_filter = client.post(
            "/api/traffic/capture/export.json",
            headers=API_HEADERS,
            json={
                "interface": "eth0",
                "authorized": True,
                "flow_controls": {"display_filter": "payload == secret"},
            },
        )

    assert unauthorized.status_code == 400
    assert invalid_filter.status_code == 400
    assert "Unsupported field" in invalid_filter.json()["detail"]
