from fastapi.testclient import TestClient

import backend.main as api


client = TestClient(api.app)


def test_scan_requires_explicit_authorization():
    response = client.post("/api/scan/network", json={"cidr": "192.168.1.0/24"})

    assert response.status_code == 403


def test_history_limit_is_bounded():
    response = client.get("/api/history?limit=0")

    assert response.status_code == 422


def test_untrusted_host_is_rejected():
    response = client.get("/api/health", headers={"host": "evil.example"})

    assert response.status_code == 400


def test_untrusted_cors_origin_is_rejected():
    response = client.options(
        "/api/scan/network",
        headers={
            "origin": "https://evil.example",
            "access-control-request-method": "POST",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


def test_advisor_uses_saved_port_findings(monkeypatch):
    assets = [{"ip_address": "192.168.1.10", "exposure_score": 4}]
    ports = [
        {
            "IP Address": "192.168.1.10",
            "Port": 3389,
            "Service": "RDP",
            "Status": "Open",
            "Risk": "High",
            "Recommendation": "Restrict RDP",
        }
    ]
    monkeypatch.setattr(api, "asset_inventory", lambda: assets)
    monkeypatch.setattr(api, "asset_open_ports", lambda: ports)

    response = client.get("/api/advisor")

    assert response.status_code == 200
    assert response.json()["risk_level"] == "Medium"
    assert "3389" in response.json()["priorities"][0]


def test_authorized_scan_uses_normalized_target(monkeypatch):
    monkeypatch.setattr(api, "scan_network", lambda target: [])
    monkeypatch.setattr(api, "add_history", lambda *args, **kwargs: None)
    monkeypatch.setattr(api, "add_scan_run", lambda *args, **kwargs: 1)
    monkeypatch.setattr(api, "upsert_hosts", lambda rows: None)

    response = client.post(
        "/api/scan/network",
        json={"cidr": "192.168.1.50/24", "authorized": True},
    )

    assert response.status_code == 200
    assert response.json()["target"] == "192.168.1.0/24"
