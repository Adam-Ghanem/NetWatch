import sqlite3
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

    assert version == 5
    assert {
        "network_observations",
        "asset_events",
        "audit_log",
        "scan_policies",
        "operation_alerts",
        "maintenance_windows",
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
