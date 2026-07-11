from __future__ import annotations

from pathlib import Path

import inventory_store
from fastapi.testclient import TestClient

import backend.main as api


API_HEADERS = {"X-NetWatch-Key": "test-secret"}


def _client(monkeypatch, tmp_path: Path) -> TestClient:
    monkeypatch.setenv("NETWATCH_API_KEY", "test-secret")
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    return TestClient(api.app)


def test_dashboard_is_served_with_security_headers(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert "Connect to NetWatch" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_frontend_assets_are_served(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/app.js")
    assert response.status_code == 200
    assert "NetWatchApi" in response.text
    assert response.headers["x-content-type-options"] == "nosniff"


def test_health_is_public(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "1.0.0"
    assert response.headers["cache-control"] == "no-store"


def test_protected_endpoint_rejects_missing_key(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/inventory")
    assert response.status_code == 401


def test_protected_endpoint_rejects_wrong_key(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/inventory", headers={"X-NetWatch-Key": "wrong"})
    assert response.status_code == 401


def test_api_is_disabled_without_configured_key(monkeypatch, tmp_path):
    monkeypatch.delenv("NETWATCH_API_KEY", raising=False)
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    with TestClient(api.app) as client:
        response = client.get("/api/inventory")
    assert response.status_code == 503


def test_scan_requires_explicit_authorization(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/scan/network",
            headers=API_HEADERS,
            json={"cidr": "192.168.1.0/30", "authorized": False},
        )
    assert response.status_code == 403


def test_authorized_scan_uses_validated_target(monkeypatch, tmp_path):
    monkeypatch.setattr(
        api,
        "scan_network",
        lambda cidr: [{"IP Address": "192.168.1.1", "Status": "Online", "Details": "mock"}],
    )
    monkeypatch.setattr(api, "add_scan_run", lambda *args, **kwargs: 1)
    monkeypatch.setattr(api, "upsert_hosts", lambda *args, **kwargs: None)

    with _client(monkeypatch, tmp_path) as client:
        response = client.post(
            "/api/scan/network",
            headers=API_HEADERS,
            json={"cidr": "192.168.1.1/30", "authorized": True},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["target"] == "192.168.1.0/30"
    assert payload["online_hosts"] == 1


def test_untrusted_origin_is_not_allowed(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.options(
            "/api/inventory",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-NetWatch-Key",
            },
        )
    assert response.headers.get("access-control-allow-origin") is None


def test_trusted_local_origin_is_allowed(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.options(
            "/api/inventory",
            headers={
                "Origin": "http://127.0.0.1:8000",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-NetWatch-Key",
            },
        )
    assert response.headers.get("access-control-allow-origin") == "http://127.0.0.1:8000"
