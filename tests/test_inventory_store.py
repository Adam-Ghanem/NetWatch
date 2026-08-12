import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import inventory_store


def _use_temporary_database(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def test_inventory_queries_enforce_requested_limits(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.upsert_hosts(
        [
            {"IP Address": "192.168.1.1"},
            {"IP Address": "192.168.1.2"},
            {"IP Address": "192.168.1.3"},
        ]
    )

    assert len(inventory_store.asset_inventory(limit=2)) == 2
    assert len(inventory_store.asset_inventory(limit=999_999)) == 3


def test_saved_port_data_cannot_override_asset_identity(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.update_asset_ports(
        "192.168.1.10",
        [
            {
                "IP Address": "203.0.113.50",
                "Port": 22,
                "Status": "Open",
                "Risk": "Medium",
            }
        ],
        exposure_score=2,
        exposure_level="Low",
    )

    findings = inventory_store.asset_port_findings()
    inventory = inventory_store.asset_inventory()

    assert findings[0]["IP Address"] == "192.168.1.10"
    assert inventory[0]["status"] == "Seen"
    assert inventory[0]["details"] == "Port audit completed"


def test_network_scans_record_new_missing_and_returned_assets(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)

    first = inventory_store.record_network_scan(
        "192.168.1.0/29",
        [
            {"IP Address": "192.168.1.1", "Status": "Online", "Details": "reply"},
            {"IP Address": "192.168.1.2", "Status": "Online", "Details": "reply"},
        ],
    )
    first_inventory = {row["ip_address"]: row for row in inventory_store.asset_inventory()}
    first_last_seen = first_inventory["192.168.1.1"]["last_seen"]
    second = inventory_store.record_network_scan(
        "192.168.1.0/29",
        [
            {"IP Address": "192.168.1.2", "Status": "Online", "Details": "reply"},
            {"IP Address": "192.168.1.3", "Status": "Online", "Details": "reply"},
        ],
    )
    inventory_after_second = {row["ip_address"]: row for row in inventory_store.asset_inventory()}
    third = inventory_store.record_network_scan(
        "192.168.1.0/29",
        [
            {"IP Address": "192.168.1.1", "Status": "Online", "Details": "reply"},
            {"IP Address": "192.168.1.2", "Status": "Online", "Details": "reply"},
            {"IP Address": "192.168.1.3", "Status": "Online", "Details": "reply"},
        ],
    )

    assert first.new_assets == ("192.168.1.1", "192.168.1.2")
    assert second.new_assets == ("192.168.1.3",)
    assert second.not_observed_assets == ("192.168.1.1",)
    assert inventory_after_second["192.168.1.1"]["status"] == "Not observed"
    assert inventory_after_second["192.168.1.1"]["last_seen"] == first_last_seen
    assert third.returned_assets == ("192.168.1.1",)
    assert third.total_changes == 1

    event_types = [event["event_type"] for event in inventory_store.recent_asset_events(20)]
    assert event_types.count("new_asset") == 3
    assert event_types.count("not_observed") == 1
    assert event_types.count("asset_returned") == 1
    assert len(inventory_store.recent_network_observations(100)) == 8


def test_repeated_missing_result_does_not_duplicate_change_event(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.record_network_scan(
        "192.168.1.0/30",
        [{"IP Address": "192.168.1.1", "Status": "Online"}],
    )

    first_missing = inventory_store.record_network_scan("192.168.1.0/30", [])
    second_missing = inventory_store.record_network_scan("192.168.1.0/30", [])

    assert first_missing.not_observed_assets == ("192.168.1.1",)
    assert second_missing.not_observed_assets == ()
    events = inventory_store.recent_asset_events(20)
    assert [event["event_type"] for event in events].count("not_observed") == 1


def test_network_snapshot_ignores_invalid_and_out_of_scope_results(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)

    result = inventory_store.record_network_scan(
        "192.168.1.0/30",
        [
            {"IP Address": "not-an-ip", "Status": "Online"},
            {"IP Address": "10.0.0.1", "Status": "Online"},
            {"IP Address": "192.168.1.1", "Status": "Online"},
            {"IP Address": "192.168.1.1", "Status": "Online", "Details": "latest"},
        ],
    )

    assert result.observed_assets == ("192.168.1.1",)
    assert [row["ip_address"] for row in inventory_store.asset_inventory()] == ["192.168.1.1"]
    assert len(inventory_store.recent_network_observations()) == 1


def test_database_schema_is_upgraded_for_change_tracking(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.init_db()

    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }

        assert version == 10
    assert {
        "network_observations",
        "asset_events",
        "audit_log",
        "audit_chain_state",
        "scan_policies",
        "operation_alerts",
        "maintenance_windows",
        "intelligence_events",
        "intelligence_daily_usage",
        "service_findings",
        "enterprise_outbox",
        "enterprise_jobs",
    }.issubset(tables)


def test_change_history_retention_is_bounded(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setattr(inventory_store, "MAX_ASSET_EVENTS", 2)
    monkeypatch.setattr(inventory_store, "MAX_NETWORK_OBSERVATIONS", 2)

    inventory_store.record_network_scan(
        "192.168.1.0/30",
        [{"IP Address": "192.168.1.1", "Status": "Online"}],
    )
    inventory_store.record_network_scan("192.168.1.0/30", [])
    inventory_store.record_network_scan(
        "192.168.1.0/30",
        [{"IP Address": "192.168.1.1", "Status": "Online"}],
    )

    assert len(inventory_store.recent_asset_events(20)) == 2
    assert len(inventory_store.recent_network_observations(20)) == 2


def test_existing_inventory_schema_migrates_without_losing_assets(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE assets (
                ip_address TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                open_ports TEXT NOT NULL DEFAULT '[]',
                exposure_score INTEGER NOT NULL DEFAULT 0,
                exposure_level TEXT NOT NULL DEFAULT 'Clean'
            )
            """)
        conn.execute(
            """
            INSERT INTO assets (
                ip_address, first_seen, last_seen, status, details,
                open_ports, exposure_score, exposure_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "192.168.1.40",
                "2026-07-01T10:00:00+00:00",
                "2026-07-01T10:00:00+00:00",
                "Online",
                "legacy asset",
                "[]",
                0,
                "Clean",
            ),
        )

    inventory_store.init_db()
    asset = inventory_store.update_asset_context(
        "192.168.1.40",
        owner="Infrastructure",
        department="IT",
        location="HQ",
        criticality="High",
        notes="Migrated safely",
        actor_role="admin",
    )

    assert asset["details"] == "legacy asset"
    assert asset["owner"] == "Infrastructure"
    assert asset["criticality"] == "High"
    assert asset["mac_address"] == "-"
    assert asset["device_name"] == "Unknown device"


def test_device_identity_is_saved_and_unknown_refreshes_do_not_erase_it(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    enriched = {
        "IP Address": "192.168.1.77",
        "Status": "Online",
        "Hostname": "Adam-iPhone",
        "MAC Address": "00:1C:B3:00:00:01",
        "Manufacturer": "Apple, Inc.",
        "Device Name": "Adam-iPhone",
        "Device Type": "Mobile device",
        "Device Family": "Apple iPhone",
        "Identity Confidence": "High",
        "Identity Source": "hostname, MAC OUI",
        "Randomized MAC": False,
    }
    inventory_store.upsert_hosts([enriched])
    inventory_store.upsert_hosts(
        [{"IP Address": "192.168.1.77", "Status": "Online", "Details": "second reply"}]
    )

    asset = inventory_store.asset_inventory()[0]

    assert asset["hostname"] == "Adam-iPhone"
    assert asset["mac_address"] == "00:1C:B3:00:00:01"
    assert asset["manufacturer"] == "Apple, Inc."
    assert asset["device_family"] == "Apple iPhone"
    assert asset["identity_confidence"] == "High"
    assert asset["randomized_mac"] is False


def test_new_mac_replaces_stale_identity_for_reused_ip(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.upsert_hosts(
        [
            {
                "IP Address": "192.168.1.78",
                "Status": "Online",
                "Hostname": "Adam-iPhone",
                "MAC Address": "00:1C:B3:00:00:01",
                "Manufacturer": "Apple, Inc.",
                "Device Name": "Adam-iPhone",
                "Device Type": "Mobile device",
                "Device Family": "Apple iPhone",
                "Identity Confidence": "High",
                "Identity Source": "hostname, MAC OUI",
            }
        ]
    )
    inventory_store.upsert_hosts(
        [
            {
                "IP Address": "192.168.1.78",
                "Status": "Online",
                "MAC Address": "10:22:33:44:55:66",
                "Manufacturer": "Unknown",
                "Device Name": "Unknown device",
                "Device Type": "Unknown device",
                "Device Family": "Unknown",
                "Identity Confidence": "Low",
                "Identity Source": "neighbor table",
            }
        ]
    )

    asset = inventory_store.asset_inventory()[0]

    assert asset["mac_address"] == "10:22:33:44:55:66"
    assert asset["hostname"] == "-"
    assert asset["manufacturer"] == "Unknown"
    assert asset["device_name"] == "Unknown device"
    assert asset["identity_confidence"] == "Low"


def test_asset_context_is_normalized_and_recorded_in_audit_log(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.upsert_hosts([{"IP Address": "192.168.1.50"}])

    asset = inventory_store.update_asset_context(
        "192.168.1.50",
        owner="  Platform\n Team  ",
        department="IT",
        location="Casablanca HQ",
        criticality="critical",
        notes="Internal service\nNo credentials stored",
        actor_role="admin",
    )
    audit = inventory_store.recent_audit_log()

    assert asset["owner"] == "Platform Team"
    assert asset["criticality"] == "Critical"
    assert asset["context_updated_at"]
    assert audit[0]["action"] == "asset_context_updated"
    assert audit[0]["target"] == "192.168.1.50"


def test_asset_context_rejects_unknown_assets_and_criticality(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.upsert_hosts([{"IP Address": "192.168.1.60"}])

    with pytest.raises(ValueError, match="Criticality"):
        inventory_store.update_asset_context(
            "192.168.1.60",
            owner="",
            department="",
            location="",
            criticality="Urgent",
            notes="",
            actor_role="admin",
        )
    with pytest.raises(KeyError):
        inventory_store.update_asset_context(
            "192.168.1.61",
            owner="",
            department="",
            location="",
            criticality="Medium",
            notes="",
            actor_role="admin",
        )


def test_audit_log_retention_is_bounded(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setattr(inventory_store, "MAX_AUDIT_LOG_ENTRIES", 2)

    for index in range(3):
        inventory_store.record_audit_event(
            "operator",
            f"check_{index}",
            "192.168.1.1",
            "completed",
            "bounded test",
        )

    audit = inventory_store.recent_audit_log(20)
    assert len(audit) == 2
    assert [item["action"] for item in audit] == ["check_2", "check_1"]


def test_audit_hmac_chain_detects_retained_row_tampering(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "NETWATCH_AUDIT_HMAC_KEY",
        "independent-audit-integrity-key-with-at-least-32-characters",
    )
    inventory_store.record_audit_event(
        "admin",
        "policy_created",
        "192.168.1.0/24",
        "completed",
        "Approved company scope.",
        actor_id="oidc:employee-1042",
        auth_method="oidc",
        request_id="request-1042",
    )
    inventory_store.record_audit_event(
        "operator",
        "policy_run",
        "192.168.1.0/24",
        "completed",
        "Authorized run completed.",
        actor_id="oidc:employee-2042",
        auth_method="oidc",
        request_id="request-2042",
    )

    before = inventory_store.verify_audit_integrity()
    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.execute("UPDATE audit_log SET details = 'changed' WHERE id = 1")
    after = inventory_store.verify_audit_integrity()

    assert before["status"] == "valid"
    assert before["protected_entries"] == 2
    assert after["status"] == "invalid"
    assert after["valid"] is False
    assert inventory_store.audit_integrity_is_ready() is False
    with pytest.raises(inventory_store.AuditIntegrityError):
        inventory_store.record_audit_event(
            "admin",
            "policy_updated",
            "192.168.1.0/24",
            "completed",
            "This write must be blocked.",
        )


def test_audit_checkpoint_detects_suffix_deletion(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "NETWATCH_AUDIT_HMAC_KEY",
        "independent-audit-integrity-key-with-at-least-32-characters",
    )
    for action in ("policy_created", "policy_run"):
        inventory_store.record_audit_event(
            "admin",
            action,
            "192.168.1.0/24",
            "completed",
            "Approved operation.",
        )

    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.execute("DELETE FROM audit_log WHERE id = (SELECT MAX(id) FROM audit_log)")

    status = inventory_store.verify_audit_integrity()
    assert status["status"] == "invalid"
    assert status["valid"] is False


def test_audit_checkpoint_treats_malformed_state_as_invalid(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "NETWATCH_AUDIT_HMAC_KEY",
        "independent-audit-integrity-key-with-at-least-32-characters",
    )
    inventory_store.record_audit_event(
        "admin", "policy_created", "192.168.1.0/24", "completed", "Approved scope."
    )
    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.execute("UPDATE audit_chain_state SET last_event_id = 'malformed'")

    status = inventory_store.verify_audit_integrity()
    assert status["status"] == "invalid"
    assert inventory_store.audit_integrity_is_ready(use_cache=False) is False


def test_audit_chain_rejects_unprotected_rows_after_protected_segment(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "NETWATCH_AUDIT_HMAC_KEY",
        "independent-audit-integrity-key-with-at-least-32-characters",
    )
    inventory_store.record_audit_event(
        "admin",
        "policy_created",
        "192.168.1.0/24",
        "completed",
        "Approved operation.",
    )
    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.execute(
            """
            INSERT INTO audit_log (
                created_at, actor_role, action, target, outcome, details
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-07-15T12:00:00+00:00",
                "admin",
                "injected",
                "192.168.1.1",
                "completed",
                "Unprotected suffix.",
            ),
        )

    status = inventory_store.verify_audit_integrity()
    assert status["status"] == "invalid"
    assert inventory_store.audit_integrity_is_ready() is False


def test_protected_audit_retention_keeps_retained_segment_verifiable(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "NETWATCH_AUDIT_HMAC_KEY",
        "independent-audit-integrity-key-with-at-least-32-characters",
    )
    monkeypatch.setattr(inventory_store, "MAX_AUDIT_LOG_ENTRIES", 2)
    for index in range(3):
        inventory_store.record_audit_event(
            "operator",
            f"check_{index}",
            "192.168.1.1",
            "completed",
            "Bounded protected test.",
        )

    status = inventory_store.verify_audit_integrity()
    assert status["status"] == "valid"
    assert status["protected_entries"] == 2


def test_audit_key_must_be_separate_from_role_keys(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    reused_key = "reused-sensitive-key-with-at-least-32-characters"
    monkeypatch.setenv("NETWATCH_AUDIT_HMAC_KEY", reused_key)
    monkeypatch.setenv("NETWATCH_API_KEY", reused_key)
    inventory_store.init_db()

    assert inventory_store.audit_integrity_enabled() is False
    assert inventory_store.audit_integrity_is_ready() is False


def test_audit_integrity_reports_unavailable_without_separate_key(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.delenv("NETWATCH_AUDIT_HMAC_KEY", raising=False)
    inventory_store.record_audit_event(
        "legacy", "host_check", "192.168.1.1", "completed", "Legacy event."
    )

    status = inventory_store.verify_audit_integrity()

    assert status["status"] == "unavailable"
    assert status["valid"] is False


def test_concurrent_protected_audit_writes_keep_one_linear_chain(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "NETWATCH_AUDIT_HMAC_KEY",
        "independent-audit-integrity-key-with-at-least-32-characters",
    )
    inventory_store.init_db()
    worker_count = 6
    start = threading.Barrier(worker_count)

    def write_event(index: int) -> None:
        start.wait(timeout=5)
        inventory_store.record_audit_event(
            "operator",
            "concurrent_check",
            f"asset-{index}",
            "completed",
            "Concurrent audit-chain test.",
        )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        list(executor.map(write_event, range(worker_count)))

    status = inventory_store.verify_audit_integrity()
    assert status["status"] == "valid"
    assert status["protected_entries"] == worker_count


def test_public_audit_readiness_is_briefly_cached_but_forced_checks_are_fresh(
    monkeypatch, tmp_path
):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "NETWATCH_AUDIT_HMAC_KEY",
        "independent-audit-integrity-key-with-at-least-32-characters",
    )
    inventory_store.record_audit_event(
        "admin", "policy_created", "192.168.1.0/24", "completed", "Approved scope."
    )
    original_check = inventory_store._audit_chain_is_valid
    check_count = 0

    def counted_check(conn, key):
        nonlocal check_count
        check_count += 1
        return original_check(conn, key)

    monkeypatch.setattr(inventory_store, "_audit_chain_is_valid", counted_check)

    assert inventory_store.audit_integrity_is_ready() is True
    assert inventory_store.audit_integrity_is_ready() is True
    assert check_count == 1
    assert inventory_store.audit_integrity_is_ready(use_cache=False) is True
    assert check_count == 2


def test_audit_identity_preserves_bounded_oidc_subject(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setenv(
        "NETWATCH_AUDIT_HMAC_KEY",
        "independent-audit-integrity-key-with-at-least-32-characters",
    )
    actor_id = f"oidc:{'s' * 160}"
    inventory_store.record_audit_event(
        "viewer",
        "inventory_viewed",
        "inventory",
        "completed",
        "Authorized view.",
        actor_id=actor_id,
        auth_method="oidc",
    )

    saved = inventory_store.recent_audit_log(include_identity=True)
    assert saved[0]["actor_id"] == actor_id


def test_service_findings_are_normalized_and_filterable(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    scan_run_id = inventory_store.add_scan_run("ports", "192.168.1.10", "port audit completed")
    inventory_store.update_asset_ports(
        "192.168.1.10",
        [
            {
                "Port": 22,
                "Protocol": "tcp",
                "Service": " SSH " + ("x" * 200),
                "Status": "Open",
                "Risk": "Medium",
                "Response Time (ms)": "12.345",
            },
            {
                "Port": 443,
                "Protocol": "TCP",
                "Service": "HTTPS",
                "Status": "Closed",
                "Risk": "None",
                "Response Time (ms)": "-",
            },
            {"Port": 70_000, "Protocol": "TCP", "Status": "Open"},
        ],
        exposure_score=2,
        exposure_level="Low",
        scan_run_id=scan_run_id,
    )

    findings = inventory_store.recent_service_findings()
    filtered = inventory_store.recent_service_findings(scan_run_id=scan_run_id)

    assert len(findings) == 2
    assert filtered == findings
    assert findings[0]["scan_run_id"] == scan_run_id
    assert findings[0]["ip_address"] == "192.168.1.10"
    assert findings[0]["port"] == 443
    assert findings[1]["port"] == 22
    assert len(findings[1]["service"]) <= 120
    assert findings[1]["response_time_ms"] == 12.35


def test_service_findings_retention_is_bounded(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setattr(inventory_store, "MAX_SERVICE_FINDINGS", 2)

    for index in range(3):
        scan_run_id = inventory_store.add_scan_run(
            "ports", f"192.168.1.{index + 1}", "port audit completed"
        )
        inventory_store.update_asset_ports(
            f"192.168.1.{index + 1}",
            [{"Port": 22, "Protocol": "TCP", "Service": "SSH", "Status": "Open"}],
            exposure_score=2,
            exposure_level="Low",
            scan_run_id=scan_run_id,
        )

    findings = inventory_store.recent_service_findings(limit=20)
    assert len(findings) == 2
    assert {item["ip_address"] for item in findings} == {"192.168.1.2", "192.168.1.3"}


def test_service_findings_reject_invalid_ip_filter(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="valid IPv4"):
        inventory_store.recent_service_findings(ip_address="not-an-ip")


def test_service_findings_without_scan_id_are_not_persisted(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.update_asset_ports(
        "192.168.1.10",
        [{"Port": 22, "Protocol": "TCP", "Service": "SSH", "Status": "Open"}],
        exposure_score=2,
        exposure_level="Low",
    )
    assert inventory_store.recent_service_findings() == []
