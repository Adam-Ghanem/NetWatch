from __future__ import annotations

import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as api
import inventory_store
import operations_store
from inventory_store import NetworkChangeSummary

TEST_API_KEY = "test-secret-with-at-least-32-characters"
OPERATOR_API_KEY = "operator-secret-with-at-least-32-characters"
VIEWER_API_KEY = "viewer-secret-with-at-least-32-characters"
API_HEADERS = {"X-NetWatch-Key": TEST_API_KEY}


def _client(monkeypatch, tmp_path: Path) -> TestClient:
    monkeypatch.delenv("NETWATCH_OPERATOR_KEY", raising=False)
    monkeypatch.delenv("NETWATCH_VIEWER_KEY", raising=False)
    monkeypatch.setenv("NETWATCH_API_KEY", TEST_API_KEY)
    api._rate_events.clear()
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    return TestClient(api.app, base_url="http://127.0.0.1")


def test_dashboard_is_served_with_security_headers(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert "Connect to NetWatch" in response.text
    assert "NetWatch v1.3" in response.text
    assert "Company context" in response.text
    assert "Operations audit log" in response.text
    assert "Company operations" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_frontend_assets_are_served(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/app.js")
    assert response.status_code == 200
    assert "NetWatchApi" in response.text
    assert "/api/session" in response.text
    assert "innerHTML" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"


def test_health_is_public(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "1.3.0"
    assert response.json()["access_enabled"] is True
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
    monkeypatch.delenv("NETWATCH_OPERATOR_KEY", raising=False)
    monkeypatch.delenv("NETWATCH_VIEWER_KEY", raising=False)
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    with TestClient(api.app, base_url="http://127.0.0.1") as client:
        response = client.get("/api/inventory")
    assert response.status_code == 503


def test_api_is_disabled_with_a_weak_or_placeholder_key(monkeypatch, tmp_path):
    monkeypatch.delenv("NETWATCH_OPERATOR_KEY", raising=False)
    monkeypatch.delenv("NETWATCH_VIEWER_KEY", raising=False)
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
    monkeypatch.setattr(api, "create_alerts_for_changes", lambda _: 1)

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


def test_session_reports_admin_capabilities(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/session", headers=API_HEADERS)

    assert response.status_code == 200
    assert response.json() == {
        "role": "admin",
        "capabilities": {
            "read": True,
            "scan": True,
            "manage_assets": True,
            "manage_alerts": True,
            "manage_operations": True,
            "backup": True,
        },
    }


def test_viewer_can_read_but_cannot_scan(monkeypatch, tmp_path):
    scanner_called = False

    def scanner(_: str) -> list[dict]:
        nonlocal scanner_called
        scanner_called = True
        return []

    monkeypatch.setattr(api, "scan_network", scanner)
    with _client(monkeypatch, tmp_path) as client:
        monkeypatch.setenv("NETWATCH_VIEWER_KEY", VIEWER_API_KEY)
        viewer_headers = {"X-NetWatch-Key": VIEWER_API_KEY}
        session = client.get("/api/session", headers=viewer_headers)
        inventory = client.get("/api/inventory", headers=viewer_headers)
        scan = client.post(
            "/api/scan/network",
            headers=viewer_headers,
            json={"cidr": "192.168.1.0/30", "authorized": True},
        )

    assert session.json()["role"] == "viewer"
    assert session.json()["capabilities"]["scan"] is False
    assert inventory.status_code == 200
    assert scan.status_code == 403
    assert scanner_called is False


def test_operator_can_scan_but_cannot_edit_asset_context(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "scan_network", lambda _: [])
    monkeypatch.setattr(
        api,
        "record_network_scan",
        lambda *args, **kwargs: NetworkChangeSummary(
            scan_run_id=1,
            observed_assets=(),
            new_assets=(),
            returned_assets=(),
            not_observed_assets=(),
        ),
    )
    with _client(monkeypatch, tmp_path) as client:
        inventory_store.upsert_hosts([{"IP Address": "192.168.1.10"}])
        monkeypatch.setenv("NETWATCH_OPERATOR_KEY", OPERATOR_API_KEY)
        operator_headers = {"X-NetWatch-Key": OPERATOR_API_KEY}
        scan = client.post(
            "/api/scan/network",
            headers=operator_headers,
            json={"cidr": "192.168.1.0/30", "authorized": True},
        )
        update = client.patch(
            "/api/assets/192.168.1.10",
            headers=operator_headers,
            json={"owner": "Operations", "criticality": "High"},
        )

    assert scan.status_code == 200
    assert update.status_code == 403


def test_admin_can_update_asset_context_and_audit_event(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        inventory_store.upsert_hosts([{"IP Address": "192.168.1.20"}])
        update = client.patch(
            "/api/assets/192.168.1.20",
            headers=API_HEADERS,
            json={
                "owner": "Platform Team",
                "department": "IT",
                "location": "Casablanca HQ",
                "criticality": "Critical",
                "notes": "Core internal service",
            },
        )
        audit = client.get("/api/audit-log", headers=API_HEADERS)

    assert update.status_code == 200
    assert update.json()["asset"]["owner"] == "Platform Team"
    assert update.json()["asset"]["criticality"] == "Critical"
    assert audit.status_code == 200
    assert audit.json()["items"][0]["action"] == "asset_context_updated"
    assert audit.json()["items"][0]["actor_role"] == "admin"


def test_inventory_csv_export_is_downloadable_and_formula_safe(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        inventory_store.upsert_hosts([{"IP Address": "192.168.1.30"}])
        inventory_store.update_asset_context(
            "192.168.1.30",
            owner="=UNTRUSTED()",
            department="Finance",
            location="HQ",
            criticality="High",
            notes="",
            actor_role="admin",
        )
        response = client.get("/api/inventory/export.csv", headers=API_HEADERS)

    assert response.status_code == 200
    assert (
        response.headers["content-disposition"] == 'attachment; filename="netwatch-inventory.csv"'
    )
    assert "'=UNTRUSTED()" in response.text


def test_admin_manages_approved_scan_policies_and_other_roles_are_isolated(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        created = client.post(
            "/api/scan-policies",
            headers=API_HEADERS,
            json={
                "name": "HQ baseline",
                "cidr": "192.168.20.9/24",
                "interval_minutes": 60,
                "enabled": True,
                "authorized": True,
            },
        )
        monkeypatch.setenv("NETWATCH_VIEWER_KEY", VIEWER_API_KEY)
        viewer_headers = {"X-NetWatch-Key": VIEWER_API_KEY}
        listed = client.get("/api/scan-policies", headers=viewer_headers)
        viewer_update = client.patch(
            f"/api/scan-policies/{created.json()['policy']['id']}",
            headers=viewer_headers,
            json={"enabled": False},
        )
        updated = client.patch(
            f"/api/scan-policies/{created.json()['policy']['id']}",
            headers=API_HEADERS,
            json={"enabled": False},
        )

    assert created.status_code == 200
    assert created.json()["policy"]["cidr"] == "192.168.20.0/24"
    assert created.json()["policy"]["authorized_by"] == "admin"
    assert listed.status_code == 200
    assert listed.json()["count"] == 1
    assert viewer_update.status_code == 403
    assert updated.status_code == 200
    assert updated.json()["policy"]["enabled"] is False


def test_scan_policy_requires_admin_and_durable_authorization(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        missing_authorization = client.post(
            "/api/scan-policies",
            headers=API_HEADERS,
            json={
                "name": "Lab baseline",
                "cidr": "10.0.0.0/24",
                "interval_minutes": 60,
                "authorized": False,
            },
        )
        public_target = client.post(
            "/api/scan-policies",
            headers=API_HEADERS,
            json={
                "name": "Invalid public target",
                "cidr": "8.8.8.0/24",
                "interval_minutes": 60,
                "authorized": True,
            },
        )
        monkeypatch.setenv("NETWATCH_OPERATOR_KEY", OPERATOR_API_KEY)
        operator_create = client.post(
            "/api/scan-policies",
            headers={"X-NetWatch-Key": OPERATOR_API_KEY},
            json={
                "name": "Operator policy",
                "cidr": "10.1.0.0/24",
                "interval_minutes": 60,
                "authorized": True,
            },
        )

    assert missing_authorization.status_code == 403
    assert public_target.status_code == 400
    assert operator_create.status_code == 403


def test_manual_policy_run_creates_alert_and_operator_can_acknowledge(monkeypatch, tmp_path):
    monkeypatch.setattr(
        api,
        "scan_network",
        lambda _: [{"IP Address": "192.168.30.1", "Status": "Online", "Details": "mock"}],
    )
    with _client(monkeypatch, tmp_path) as client:
        policy = client.post(
            "/api/scan-policies",
            headers=API_HEADERS,
            json={
                "name": "Approved branch office",
                "cidr": "192.168.30.0/30",
                "interval_minutes": 60,
                "enabled": False,
                "authorized": True,
            },
        ).json()["policy"]
        run = client.post(
            f"/api/scan-policies/{policy['id']}/run",
            headers=API_HEADERS,
            json={"authorized": True},
        )
        alerts = client.get("/api/alerts?status=open", headers=API_HEADERS)
        alert_id = alerts.json()["items"][0]["id"]

        monkeypatch.setenv("NETWATCH_OPERATOR_KEY", OPERATOR_API_KEY)
        acknowledged = client.patch(
            f"/api/alerts/{alert_id}",
            headers={"X-NetWatch-Key": OPERATOR_API_KEY},
            json={"status": "acknowledged"},
        )
        monkeypatch.setenv("NETWATCH_VIEWER_KEY", VIEWER_API_KEY)
        viewer_update = client.patch(
            f"/api/alerts/{alert_id}",
            headers={"X-NetWatch-Key": VIEWER_API_KEY},
            json={"status": "open"},
        )

    assert run.status_code == 200
    assert run.json()["alerts_created"] == 1
    assert alerts.status_code == 200
    assert alerts.json()["open_count"] == 1
    assert acknowledged.status_code == 200
    assert acknowledged.json()["alert"]["acknowledged_by"] == "operator"
    assert viewer_update.status_code == 403


def test_database_backup_is_admin_only_and_downloadable(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        inventory_store.upsert_hosts([{"IP Address": "192.168.1.200"}])
        backup = client.get("/api/backups/database", headers=API_HEADERS)
        monkeypatch.setenv("NETWATCH_VIEWER_KEY", VIEWER_API_KEY)
        viewer_backup = client.get(
            "/api/backups/database", headers={"X-NetWatch-Key": VIEWER_API_KEY}
        )

    backup_path = tmp_path / "api-backup.sqlite3"
    backup_path.write_bytes(backup.content)
    with sqlite3.connect(backup_path) as conn:
        saved = conn.execute(
            "SELECT ip_address FROM assets WHERE ip_address = '192.168.1.200'"
        ).fetchone()

    assert backup.status_code == 200
    assert backup.headers["content-type"] == "application/vnd.sqlite3"
    assert "netwatch-backup-" in backup.headers["content-disposition"]
    assert saved == ("192.168.1.200",)
    assert viewer_backup.status_code == 403


def test_due_scheduler_cycle_runs_claimed_policy_with_system_audit(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    monkeypatch.setattr(api, "scan_network", lambda _: [])
    policy = operations_store.create_scan_policy(
        name="Scheduled lab baseline",
        cidr="10.20.0.0/30",
        interval_minutes=60,
        enabled=True,
        authorized_by="admin",
    )
    with inventory_store._connect() as conn:
        conn.execute(
            "UPDATE scan_policies SET next_run_at = ? WHERE id = ?",
            ("2000-01-01T00:00:00+00:00", policy["id"]),
        )

    completed = api.run_due_scan_policies_once()
    saved = operations_store.get_scan_policy(policy["id"])
    audit = inventory_store.recent_audit_log()

    assert completed == 1
    assert saved["last_status"] == "completed"
    assert audit[0]["actor_role"] == "scheduler"
    assert audit[0]["action"] == "scheduled_network_scan"
