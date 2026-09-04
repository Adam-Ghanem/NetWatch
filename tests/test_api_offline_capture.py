from __future__ import annotations

import socket
import struct
from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as api
import inventory_store
from pcap_import import MAX_PCAP_BYTES

TEST_API_KEY = "test-secret-with-at-least-32-characters"
AUDIT_HMAC_KEY = "test-independent-audit-hmac-key-with-enough-characters"
API_HEADERS = {
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


def _tcp_frame() -> bytes:
    destination_mac = bytes.fromhex("286C07000001")
    source_mac = bytes.fromhex("001CB3000001")
    ethernet = destination_mac + source_mac + struct.pack("!H", 0x0800)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        1,
        0,
        64,
        6,
        0,
        socket.inet_aton("192.168.1.10"),
        socket.inet_aton("192.168.1.20"),
    )
    tcp = struct.pack("!HHLLBBHHH", 51_515, 443, 0, 0, 0x50, 0x12, 65_535, 0, 0)
    return ethernet + ipv4 + tcp


def _pcap(*frames: bytes) -> bytes:
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
    chunks = [global_header]
    for index, frame in enumerate(frames):
        chunks.append(struct.pack("<IIII", 1_788_304_800 + index, 250_000, len(frame), len(frame)))
        chunks.append(frame)
    return b"".join(chunks)


def test_offline_capture_analysis_is_authenticated_bounded_and_metadata_only(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/traffic/offline/analyze",
            headers=API_HEADERS,
            params={
                "authorized": "true",
                "packet_limit": 10,
                "display_filter": "protocol == tcp and id.resp_p == 443",
                "flow_limit": 5,
            },
            content=_pcap(_tcp_frame()),
        )

    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "pcap"
    assert body["captured_packets"] == 1
    assert body["flow_count"] == 1
    assert body["flows"][0]["responder"]["port"] == 443
    assert body["payload_retained"] is False
    assert "payload" not in body["packets"][0]
    assert "raw" not in body["packets"][0]


def test_offline_capture_analysis_requires_explicit_authorization(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/traffic/offline/analyze",
            headers=API_HEADERS,
            content=_pcap(_tcp_frame()),
        )

    assert response.status_code == 403


def test_offline_capture_analysis_rejects_oversized_upload(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/traffic/offline/analyze?authorized=true",
            headers=API_HEADERS,
            content=bytes(MAX_PCAP_BYTES + 1),
        )

    assert response.status_code == 413
    assert "safety limit" in response.json()["detail"].lower()


def test_offline_capture_export_reuses_filters_and_stays_metadata_only(
    monkeypatch, tmp_path
):
    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/traffic/offline/export.json",
            headers=API_HEADERS,
            params={
                "authorized": "true",
                "packet_limit": 10,
                "display_filter": "protocol == tcp and id.resp_p == 443",
                "flow_limit": 5,
            },
            content=_pcap(_tcp_frame()),
        )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["content-disposition"] == (
        'attachment; filename="netwatch-offline-flows.json"'
    )
    body = response.json()
    assert len(body) == 1
    assert body[0]["responder"]["port"] == 443
    assert "community_id" in body[0]
    assert "payload" not in body[0]
    assert "raw" not in body[0]


def test_offline_capture_export_supports_ndjson_and_requires_authorization(
    monkeypatch, tmp_path
):
    capture = _pcap(_tcp_frame())
    with _client(monkeypatch, tmp_path) as client:
        denied = client.post(
            "/api/traffic/offline/export.ndjson",
            headers=API_HEADERS,
            content=capture,
        )
        response = client.post(
            "/api/traffic/offline/export.ndjson",
            headers=API_HEADERS,
            params={"authorized": "true", "packet_limit": 10, "flow_limit": 1},
            content=capture,
        )

    assert denied.status_code == 403
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert response.headers["content-disposition"] == (
        'attachment; filename="netwatch-offline-flows.ndjson"'
    )
    lines = [line for line in response.text.splitlines() if line]
    assert len(lines) == 1
    assert '"community_id"' in lines[0]
    assert '"payload"' not in lines[0]
