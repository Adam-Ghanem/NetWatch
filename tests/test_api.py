from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import backend.main as api
import inventory_store
import operations_store
from ai_advisor import AIProviderResult, IntelligenceBrief, safety_identifier
from enterprise_auth import OIDCAuthenticationError, OIDCIdentity
from inventory_store import NetworkChangeSummary

TEST_API_KEY = "test-secret-with-at-least-32-characters"
OPERATOR_API_KEY = "operator-secret-with-at-least-32-characters"
VIEWER_API_KEY = "viewer-secret-with-at-least-32-characters"
AI_PROVIDER_KEY = "test-openai-project-key-with-enough-characters"
AI_SAFETY_SECRET = "test-independent-safety-secret-with-enough-characters"
AI_SUBJECT_ID = "deployment_subject_12345"
AUDIT_HMAC_KEY = "test-independent-audit-hmac-key-with-enough-characters"
API_HEADERS = {"X-NetWatch-Key": TEST_API_KEY}


def _client(monkeypatch, tmp_path: Path) -> TestClient:
    monkeypatch.delenv("NETWATCH_OPERATOR_KEY", raising=False)
    monkeypatch.delenv("NETWATCH_VIEWER_KEY", raising=False)
    monkeypatch.setenv("NETWATCH_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("NETWATCH_AUDIT_HMAC_KEY", AUDIT_HMAC_KEY)
    monkeypatch.setenv("NETWATCH_OIDC_ENABLED", "false")
    monkeypatch.setenv("NETWATCH_AI_SAFETY_SECRET", AI_SAFETY_SECRET)
    monkeypatch.setenv("NETWATCH_AI_SUBJECT_ID", AI_SUBJECT_ID)
    api._rate_events.clear()
    api._intelligence_rate_events.clear()
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    return TestClient(api.app, base_url="http://127.0.0.1")


def test_dashboard_is_served_with_security_headers(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert "Connect to NetWatch" in response.text
    assert "NetWatch v1.6" in response.text
    assert "Company context" in response.text
    assert "Operations audit log" in response.text
    assert "Company operations" in response.text
    assert "NetWatch Intelligence" in response.text
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")
    assert len(response.headers["x-request-id"]) == 32


def test_frontend_assets_are_served(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/app.js")
    assert response.status_code == 200
    assert "NetWatchApi" in response.text
    assert "/api/session" in response.text
    assert "innerHTML" not in response.text
    assert "URLSearchParams(window.location.search)" not in response.text
    assert "candidate.origin !== window.location.origin" in response.text
    assert response.headers["x-content-type-options"] == "nosniff"


def test_health_is_public(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.json()["version"] == "1.6.0"
    assert response.json()["access_enabled"] is True
    assert response.json()["auth_methods"] == ["api_key"]
    assert response.headers["cache-control"] == "no-store"


def test_liveness_and_readiness_are_public_and_separate(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        live = client.get("/api/health/live")
        ready = client.get("/api/health/ready")

    assert live.status_code == 200
    assert live.json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.json()["database"] == "ready"
    assert ready.json()["role_keys"] == "configured"
    assert ready.json()["audit_integrity"] == "ready"


def test_protected_endpoint_rejects_missing_key(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/inventory")
    assert response.status_code == 401


def test_protected_endpoint_rejects_wrong_key(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get("/api/inventory", headers={"X-NetWatch-Key": "wrong"})
    assert response.status_code == 401


def test_malformed_authorization_never_falls_back_to_shared_key(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        response = client.get(
            "/api/session",
            headers={"Authorization": "Basic unexpected", **API_HEADERS},
        )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_duplicate_role_key_values_fail_readiness_and_authentication(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        monkeypatch.setenv("NETWATCH_OPERATOR_KEY", TEST_API_KEY)
        ready = client.get("/api/health/ready")
        session = client.get("/api/session", headers=API_HEADERS)

    assert ready.status_code == 503
    assert ready.json()["role_keys"] == "invalid"
    assert session.status_code == 503


def test_invalid_oidc_configuration_fails_closed_for_shared_keys(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        monkeypatch.setenv("NETWATCH_OIDC_ENABLED", "treu")
        ready = client.get("/api/health/ready")
        session = client.get("/api/session", headers=API_HEADERS)

    assert ready.status_code == 503
    assert ready.json()["oidc"] == "invalid"
    assert session.status_code == 503


def test_rate_limit_identity_buckets_are_bounded_and_stale_entries_are_reclaimed(
    monkeypatch,
):
    api._rate_events.clear()
    monkeypatch.setattr(api, "_MAX_API_RATE_LIMIT_BUCKETS", 2)
    monkeypatch.setattr(api.time, "monotonic", lambda: 1_000.0)

    api._enforce_rate_limit("identity-a")
    api._enforce_rate_limit("identity-b")
    with pytest.raises(api.HTTPException) as error:
        api._enforce_rate_limit("identity-c")
    assert error.value.status_code == 429
    assert len(api._rate_events) == 2

    api._rate_events["identity-a"].clear()
    api._enforce_rate_limit("identity-c")
    assert set(api._rate_events) == {"identity-b", "identity-c"}


def test_api_is_disabled_without_configured_key(monkeypatch, tmp_path):
    monkeypatch.delenv("NETWATCH_API_KEY", raising=False)
    monkeypatch.delenv("NETWATCH_OPERATOR_KEY", raising=False)
    monkeypatch.delenv("NETWATCH_VIEWER_KEY", raising=False)
    monkeypatch.setenv("NETWATCH_OIDC_ENABLED", "false")
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
    monkeypatch.setattr(
        api,
        "create_alerts_for_changes",
        lambda _: operations_store.AlertChangeSummary(created=1),
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
            "view_audit_identity": True,
            "use_intelligence": True,
        },
        "auth_method": "api_key",
        "actor_id": "shared-key:admin",
    }


def test_verified_oidc_identity_maps_to_individual_session(monkeypatch, tmp_path):
    monkeypatch.setattr(
        api,
        "verify_oidc_token",
        lambda _: OIDCIdentity(subject="employee-1042", role="operator"),
    )
    with _client(monkeypatch, tmp_path) as client:
        response = client.get(
            "/api/session",
            headers={"Authorization": "Bearer signed-company-token"},
        )

    assert response.status_code == 200
    assert response.json()["role"] == "operator"
    assert response.json()["actor_id"] == "oidc:employee-1042"
    assert response.json()["auth_method"] == "oidc"


def test_invalid_bearer_token_never_falls_back_to_supplied_shared_key(monkeypatch, tmp_path):
    def reject(_: str):
        raise OIDCAuthenticationError("invalid")

    monkeypatch.setattr(api, "verify_oidc_token", reject)
    with _client(monkeypatch, tmp_path) as client:
        response = client.get(
            "/api/session",
            headers={
                "Authorization": "Bearer invalid-token",
                "X-NetWatch-Key": TEST_API_KEY,
            },
        )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_ambiguous_authorization_headers_are_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(
        api,
        "verify_oidc_token",
        lambda _: OIDCIdentity(subject="employee-1042", role="admin"),
    )
    with _client(monkeypatch, tmp_path) as client:
        response = client.get(
            "/api/session",
            headers=[
                ("Authorization", "Bearer token-one"),
                ("Authorization", "Bearer token-two"),
            ],
        )

    assert response.status_code == 401


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
    assert audit.json()["items"][0]["actor_id"] == "shared-key:admin"
    assert audit.json()["items"][0]["auth_method"] == "api_key"
    assert audit.json()["items"][0]["integrity_protected"] is True


def test_audit_identity_and_integrity_are_admin_only(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        monkeypatch.setenv("NETWATCH_OPERATOR_KEY", OPERATOR_API_KEY)
        operator_headers = {"X-NetWatch-Key": OPERATOR_API_KEY}
        audit = client.get("/api/audit-log", headers=operator_headers)
        integrity = client.get("/api/audit-log/integrity", headers=operator_headers)

    assert audit.status_code == 403
    assert integrity.status_code == 403


def test_tampered_audit_chain_pauses_privileged_operations_but_remains_inspectable(
    monkeypatch, tmp_path
):
    profiler_called = False

    def fake_profile(_):
        nonlocal profiler_called
        profiler_called = True

    monkeypatch.setattr(api, "profile_host", fake_profile)
    with _client(monkeypatch, tmp_path) as client:
        inventory_store.record_audit_event(
            "admin",
            "policy_created",
            "192.168.1.0/24",
            "completed",
            "Approved scope.",
        )
        with sqlite3.connect(inventory_store.DB_FILE) as conn:
            conn.execute("UPDATE audit_log SET details = 'tampered' WHERE id = 1")

        ready = client.get("/api/health/ready")
        blocked = client.post(
            "/api/scan/host",
            headers=API_HEADERS,
            json={"ip": "192.168.1.1", "authorized": True},
        )
        integrity = client.get("/api/audit-log/integrity", headers=API_HEADERS)

    assert ready.status_code == 503
    assert blocked.status_code == 503
    assert profiler_called is False
    assert integrity.status_code == 200
    assert integrity.json()["status"] == "invalid"


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
    assert created.json()["policy"]["authorized_by"] == "shared-key:admin"
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
    assert acknowledged.json()["alert"]["acknowledged_by"] == "shared-key:operator"
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
    monkeypatch.setenv("NETWATCH_AUDIT_HMAC_KEY", AUDIT_HMAC_KEY)
    monkeypatch.delenv("NETWATCH_API_KEY", raising=False)
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


def test_admin_maintenance_window_pauses_manual_policy_runs(monkeypatch, tmp_path):
    monkeypatch.setattr(api, "scan_network", lambda _: [])
    now = datetime.now(timezone.utc)
    with _client(monkeypatch, tmp_path) as client:
        policy = client.post(
            "/api/scan-policies",
            headers=API_HEADERS,
            json={
                "name": "Maintenance-aware HQ",
                "cidr": "10.44.0.0/30",
                "interval_minutes": 60,
                "enabled": True,
                "authorized": True,
            },
        ).json()["policy"]
        created = client.post(
            "/api/maintenance-windows",
            headers=API_HEADERS,
            json={
                "name": "Approved firewall change",
                "starts_at": (now - timedelta(minutes=5)).isoformat(),
                "ends_at": (now + timedelta(hours=1)).isoformat(),
                "reason": "CHG-1042",
                "policy_id": policy["id"],
                "enabled": True,
            },
        )
        listed = client.get("/api/maintenance-windows", headers=API_HEADERS)
        policies = client.get("/api/scan-policies", headers=API_HEADERS)
        blocked = client.post(
            f"/api/scan-policies/{policy['id']}/run",
            headers=API_HEADERS,
            json={"authorized": True},
        )

        monkeypatch.setenv("NETWATCH_VIEWER_KEY", VIEWER_API_KEY)
        viewer_create = client.post(
            "/api/maintenance-windows",
            headers={"X-NetWatch-Key": VIEWER_API_KEY},
            json={
                "name": "Unauthorized window",
                "starts_at": now.isoformat(),
                "ends_at": (now + timedelta(hours=1)).isoformat(),
            },
        )
        disabled = client.patch(
            f"/api/maintenance-windows/{created.json()['window']['id']}",
            headers=API_HEADERS,
            json={"enabled": False},
        )
        allowed = client.post(
            f"/api/scan-policies/{policy['id']}/run",
            headers=API_HEADERS,
            json={"authorized": True},
        )

    assert created.status_code == 200
    assert created.json()["window"]["active"] is True
    assert listed.json()["active_count"] == 1
    assert policies.json()["items"][0]["maintenance_active"] is True
    assert blocked.status_code == 409
    assert viewer_create.status_code == 403
    assert disabled.json()["window"]["enabled"] is False
    assert allowed.status_code == 200


def test_alert_case_assignment_resolution_and_filters(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        run_id = inventory_store.add_scan_run("network", "192.168.60.0/24", "case test")
        changes = NetworkChangeSummary(
            scan_run_id=run_id,
            observed_assets=("192.168.60.10",),
            new_assets=("192.168.60.10",),
            returned_assets=(),
            not_observed_assets=(),
        )
        operations_store.create_alerts_for_changes(changes)
        alert_id = client.get("/api/alerts?status=open", headers=API_HEADERS).json()["items"][0][
            "id"
        ]
        missing_evidence = client.patch(
            f"/api/alerts/{alert_id}",
            headers=API_HEADERS,
            json={"status": "resolved", "assigned_to": "SOC"},
        )
        monkeypatch.setenv("NETWATCH_OPERATOR_KEY", OPERATOR_API_KEY)
        resolved = client.patch(
            f"/api/alerts/{alert_id}",
            headers={"X-NetWatch-Key": OPERATOR_API_KEY},
            json={
                "status": "resolved",
                "assigned_to": "Network Operations",
                "resolution_note": "Asset validated with its business owner.",
            },
        )
        resolved_list = client.get("/api/alerts?status=resolved", headers=API_HEADERS)

    assert missing_evidence.status_code == 400
    assert resolved.status_code == 200
    assert resolved.json()["alert"]["assigned_to"] == "Network Operations"
    assert resolved.json()["alert"]["sla_state"] == "resolved"
    assert resolved_list.json()["resolved_count"] == 1
    assert resolved_list.json()["items"][0]["resolution_note"]


def test_authenticated_metrics_are_bounded_and_do_not_export_targets(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as client:
        inventory_store.upsert_hosts([{"IP Address": "192.168.70.10", "Status": "Online"}])
        unauthorized = client.get("/api/metrics")
        response = client.get("/api/metrics", headers=API_HEADERS)

    assert unauthorized.status_code == 401
    assert response.status_code == 200
    assert "netwatch_assets_total 1" in response.text
    assert "netwatch_scheduler_enabled" in response.text
    assert "netwatch_intelligence_provider_requests_total" in response.text
    assert "192.168.70.10" not in response.text
    assert response.headers["cache-control"] == "no-store"


def _provider_brief() -> IntelligenceBrief:
    return IntelligenceBrief(
        risk_level="Medium",
        executive_summary="The saved evidence supports a bounded defensive review.",
        key_observations=["One asset is represented in the de-identified snapshot."],
        recommended_actions=[
            {
                "priority": "Next",
                "title": "Validate saved exposure",
                "rationale": "Observed services require owner confirmation.",
                "validation": "Record the approved service purpose and expected controls.",
            }
        ],
        limitations=["The evidence is observational and requires human validation."],
    )


def test_intelligence_status_and_brief_require_netwatch_auth(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", AI_PROVIDER_KEY)
    with _client(monkeypatch, tmp_path) as client:
        status = client.get("/api/intelligence/status")
        brief = client.post("/api/intelligence/brief", json={"refresh": False})

    assert status.status_code == 401
    assert brief.status_code == 401


def test_intelligence_is_optional_and_local_advisor_remains_available(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with _client(monkeypatch, tmp_path) as client:
        status = client.get("/api/intelligence/status", headers=API_HEADERS)
        brief = client.post(
            "/api/intelligence/brief",
            headers=API_HEADERS,
            json={"refresh": False},
        )
        local = client.get("/api/advisor", headers=API_HEADERS)

    assert status.status_code == 200
    assert status.json()["available"] is False
    assert status.json()["local_advisor_available"] is True
    assert brief.status_code == 503
    assert local.status_code == 200


def test_users_receive_cached_intelligence_without_provider_keys(monkeypatch, tmp_path):
    provider_key = AI_PROVIDER_KEY
    monkeypatch.setenv("OPENAI_API_KEY", provider_key)
    calls: list[dict] = []

    def fake_provider(snapshot, **kwargs):
        calls.append({"snapshot": snapshot, **kwargs})
        return AIProviderResult(
            brief=_provider_brief(),
            provider_request_id="resp_test_123",
            input_tokens=120,
            output_tokens=60,
        )

    monkeypatch.setattr(api, "request_intelligence_brief", fake_provider)
    with _client(monkeypatch, tmp_path) as client:
        inventory_store.upsert_hosts([{"IP Address": "192.168.88.10", "Status": "Online"}])
        inventory_store.update_asset_context(
            "192.168.88.10",
            owner="Sensitive Owner",
            department="Finance",
            location="Private HQ",
            criticality="High",
            notes="Private operational note",
            actor_role="admin",
        )
        generated = client.post(
            "/api/intelligence/brief",
            headers=API_HEADERS,
            json={"refresh": False},
        )
        monkeypatch.setenv("NETWATCH_VIEWER_KEY", VIEWER_API_KEY)
        viewer_headers = {"X-NetWatch-Key": VIEWER_API_KEY}
        cached = client.post(
            "/api/intelligence/brief",
            headers=viewer_headers,
            json={"refresh": False},
        )
        status = client.get("/api/intelligence/status", headers=viewer_headers)
        audit = client.get("/api/audit-log", headers=API_HEADERS)

    assert generated.status_code == 200
    assert generated.json()["cached"] is False
    assert cached.status_code == 200
    assert cached.json()["cached"] is True
    assert len(calls) == 1
    sent = str(calls[0]["snapshot"])
    assert "192.168.88.10" not in sent
    assert "Sensitive Owner" not in sent
    assert "Finance" not in sent
    assert "Private operational note" not in sent
    assert calls[0]["api_key"] == provider_key
    assert calls[0]["safety_id"] == safety_identifier(
        safety_secret=AI_SAFETY_SECRET,
        subject_id=AI_SUBJECT_ID,
    )
    assert provider_key not in generated.text
    assert provider_key not in cached.text
    assert status.json()["daily_requests_used"] == 1
    assert audit.json()["items"][0]["action"] == "intelligence_brief_generated"


def test_only_admin_can_force_an_intelligence_refresh(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", AI_PROVIDER_KEY)
    monkeypatch.setenv("NETWATCH_OPERATOR_KEY", OPERATOR_API_KEY)
    provider_called = False

    def fake_provider(*_, **__):
        nonlocal provider_called
        provider_called = True
        return AIProviderResult(
            brief=_provider_brief(),
            provider_request_id="resp_test_456",
            input_tokens=1,
            output_tokens=1,
        )

    monkeypatch.setattr(api, "request_intelligence_brief", fake_provider)
    with _client(monkeypatch, tmp_path) as client:
        monkeypatch.setenv("NETWATCH_OPERATOR_KEY", OPERATOR_API_KEY)
        response = client.post(
            "/api/intelligence/brief",
            headers={"X-NetWatch-Key": OPERATOR_API_KEY},
            json={"refresh": True},
        )

    assert response.status_code == 403
    assert provider_called is False


def test_intelligence_fails_closed_without_an_independent_safety_identity(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("OPENAI_API_KEY", AI_PROVIDER_KEY)
    with _client(monkeypatch, tmp_path) as client:
        monkeypatch.setenv("NETWATCH_AI_SAFETY_SECRET", AI_PROVIDER_KEY)
        equal_secret = client.get("/api/intelligence/status", headers=API_HEADERS)
        monkeypatch.delenv("NETWATCH_AI_SAFETY_SECRET", raising=False)
        missing_secret = client.post(
            "/api/intelligence/brief",
            headers=API_HEADERS,
            json={"refresh": False},
        )

    assert equal_secret.status_code == 200
    assert equal_secret.json()["available"] is False
    assert missing_secret.status_code == 503
    assert AI_PROVIDER_KEY not in missing_secret.text


def test_daily_budget_rejects_before_a_second_provider_call(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", AI_PROVIDER_KEY)
    monkeypatch.setattr(api, "AI_DAILY_REQUEST_LIMIT", 1)
    provider_calls = 0

    def fake_provider(*_, **__):
        nonlocal provider_calls
        provider_calls += 1
        return AIProviderResult(
            brief=_provider_brief(),
            provider_request_id="resp_budget_test",
            input_tokens=1,
            output_tokens=1,
        )

    monkeypatch.setattr(api, "request_intelligence_brief", fake_provider)
    with _client(monkeypatch, tmp_path) as client:
        first = client.post(
            "/api/intelligence/brief",
            headers=API_HEADERS,
            json={"refresh": True},
        )
        second = client.post(
            "/api/intelligence/brief",
            headers=API_HEADERS,
            json={"refresh": True},
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert provider_calls == 1
