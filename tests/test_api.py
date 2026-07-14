from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as api
import inventory_store
from inventory_store import NetworkChangeSummary

TEST_API_KEY = "test-secret-with-at-least-32-characters"
API_HEADERS = {"X-NetWatch-Key": TEST_API_KEY}


def _client(monkeypatch, tmp_path: Path) -> TestClient:
    monkeypatch.setenv("NETWATCH_API_KEY", TEST_API_KEY)
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    return TestClient(api.app, base_url="http://127.0.0.1")


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
    assert response.json()["version"] == "1.1.0"
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
    with TestClient(api.app, base_url="http://127.0.0.1") as client:
        response = client.get("/api/inventory")
    assert response.status_code == 503


def test_api_is_disabled_with_a_weak_or_placeholder_key(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")

    for key in ("short-key", "replace-with-a-long-random-secret"):
        monkeypatch.setenv("NETWATCH_API_KEY", key)
        with TestClient(api.app, base_url="http://127.0.0.1") as client:
            response = client.get("/api/inventory", headers={"X-NetWatch-Key": key})
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
    monkeypatch.setattr(
        api,
        "record_network_scan",
        lambda *args, **kwargs: NetworkChangeSummary(
            scan_run_id=1,
            observed_assets=("192.168.1.1",),
            new_assets=("192.168.1.1",),
            returned_assets=(),
            not_observed_assets=(),
        ),
    )

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
    assert payload["changes"]["new_assets"] == ["192.168.1.1"]
    assert payload["changes"]["total_changes"] == 1


def test_change_and_observation_endpoints_return_saved_evidence(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    inventory_store.record_network_scan(
        "192.168.1.0/30",
        [{"IP Address": "192.168.1.1", "Status": "Online", "Details": "mock"}],
    )

    with _client(monkeypatch, tmp_path) as client:
        changes = client.get("/api/changes", headers=API_HEADERS)
        observations = client.get("/api/observations", headers=API_HEADERS)

    assert changes.status_code == 200
    assert changes.json()["items"][0]["event_label"] == "New asset"
    assert observations.status_code == 200
    assert observations.json()["items"][0]["observed"] == 1
    assert observations.json()["items"][0]["target"] == "192.168.1.0/30"


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


def test_untrusted_host_header_is_rejected(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/health", headers={"Host": "evil.example"})
    assert response.status_code == 400


def test_inventory_limit_is_forwarded_to_storage(monkeypatch, tmp_path):
    limits: list[int] = []

    def record_limit(limit: int) -> list[dict]:
        limits.append(limit)
        return []

    monkeypatch.setattr(api, "asset_inventory", record_limit)

    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/inventory?limit=25", headers=API_HEADERS)

    assert response.status_code == 200
    assert limits == [25]


def test_inventory_limit_rejects_oversized_requests(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/inventory?limit=2001", headers=API_HEADERS)

    assert response.status_code == 422
