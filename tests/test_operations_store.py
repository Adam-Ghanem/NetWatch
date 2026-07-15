from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

import inventory_store
import operations_store


def _use_temporary_database(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def test_scan_policy_lifecycle_and_due_claim(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    policy = operations_store.create_scan_policy(
        name="Casablanca office baseline",
        cidr="192.168.10.0/24",
        interval_minutes=60,
        enabled=True,
        authorized_by="admin",
    )

    assert policy["enabled"] is True
    assert policy["authorized_by"] == "admin"
    assert policy["last_status"] == "scheduled"
    assert policy["next_run_at"]

    claimed = operations_store.claim_due_scan_policies(now="2099-01-01T00:00:00+00:00", limit=1)
    assert [item["id"] for item in claimed] == [policy["id"]]
    assert claimed[0]["last_status"] == "running"
    assert claimed[0]["last_run_at"] == "2099-01-01T00:00:00+00:00"
    assert claimed[0]["next_run_at"] == "2099-01-01T01:00:00+00:00"

    completed = operations_store.complete_scan_policy(
        policy["id"], status="completed", summary="3 hosts observed"
    )
    assert completed["last_status"] == "completed"
    assert completed["last_summary"] == "3 hosts observed"

    disabled = operations_store.update_scan_policy(policy["id"], enabled=False)
    assert disabled["enabled"] is False
    assert disabled["next_run_at"] == ""
    assert disabled["last_status"] == "disabled"


def test_scan_policy_rejects_duplicate_targets_and_unsafe_intervals(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    operations_store.create_scan_policy(
        name="Approved office range",
        cidr="10.10.0.0/24",
        interval_minutes=60,
        enabled=False,
        authorized_by="admin",
    )

    with pytest.raises(ValueError, match="already exists"):
        operations_store.create_scan_policy(
            name="Duplicate approval",
            cidr="10.10.0.0/24",
            interval_minutes=60,
            enabled=False,
            authorized_by="admin",
        )
    with pytest.raises(ValueError, match="between"):
        operations_store.create_scan_policy(
            name="Unsafe interval",
            cidr="10.20.0.0/24",
            interval_minutes=1,
            enabled=False,
            authorized_by="admin",
        )


def test_change_alerts_prioritize_critical_assets_and_support_acknowledgement(
    monkeypatch, tmp_path
):
    _use_temporary_database(monkeypatch, tmp_path)
    first = inventory_store.record_network_scan(
        "192.168.50.0/30",
        [{"IP Address": "192.168.50.1", "Status": "Online"}],
    )
    operations_store.create_alerts_for_changes(first)
    inventory_store.update_asset_context(
        "192.168.50.1",
        owner="Network Operations",
        department="IT",
        location="HQ",
        criticality="Critical",
        notes="Core gateway",
        actor_role="admin",
    )
    missing = inventory_store.record_network_scan("192.168.50.0/30", [])

    summary = operations_store.create_alerts_for_changes(missing)
    assert summary.created == 1
    assert summary.refreshed == 0
    alerts = operations_store.recent_alerts(status="open")
    critical = next(item for item in alerts if item["category"] == "asset_not_observed")
    assert critical["severity"] == "Critical"
    assert critical["target"] == "192.168.50.1"
    assert "Network Operations" in critical["details"]

    updated = operations_store.set_alert_status(
        critical["id"], status="acknowledged", actor_role="operator"
    )
    assert updated["status"] == "acknowledged"
    assert updated["acknowledged_by"] == "operator"
    assert updated["acknowledged_at"]


def test_alert_retention_is_bounded(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    monkeypatch.setattr(operations_store, "MAX_OPERATION_ALERTS", 2)

    for index in range(3):
        scan_run_id = inventory_store.add_scan_run(
            "network", f"192.168.{index}.0/24", "retention test"
        )
        changes = inventory_store.NetworkChangeSummary(
            scan_run_id=scan_run_id,
            observed_assets=(f"192.168.1.{index + 1}",),
            new_assets=(f"192.168.1.{index + 1}",),
            returned_assets=(),
            not_observed_assets=(),
        )
        operations_store.create_alerts_for_changes(changes)

    assert len(operations_store.recent_alerts(limit=20)) == 2


def test_database_backup_is_a_readable_consistent_snapshot(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.upsert_hosts([{"IP Address": "192.168.1.90", "Status": "Online"}])

    content = operations_store.database_backup_bytes()
    backup_path = tmp_path / "downloaded-backup.sqlite3"
    backup_path.write_bytes(content)

    with sqlite3.connect(backup_path) as conn:
        asset = conn.execute(
            "SELECT ip_address FROM assets WHERE ip_address = '192.168.1.90'"
        ).fetchone()
        version = conn.execute("PRAGMA user_version").fetchone()[0]

    assert asset == ("192.168.1.90",)
    assert version == 5


def test_alert_cases_are_deduplicated_and_require_resolution_evidence(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    first_run = inventory_store.add_scan_run("network", "192.168.2.0/24", "first")
    second_run = inventory_store.add_scan_run("network", "192.168.2.0/24", "second")
    first_change = inventory_store.NetworkChangeSummary(
        scan_run_id=first_run,
        observed_assets=("192.168.2.10",),
        new_assets=("192.168.2.10",),
        returned_assets=(),
        not_observed_assets=(),
    )
    repeated_change = inventory_store.NetworkChangeSummary(
        scan_run_id=second_run,
        observed_assets=("192.168.2.10",),
        new_assets=("192.168.2.10",),
        returned_assets=(),
        not_observed_assets=(),
    )

    first = operations_store.create_alerts_for_changes(first_change)
    repeated = operations_store.create_alerts_for_changes(repeated_change)
    alert = operations_store.recent_alerts(status="open")[0]

    assert first.created == 1
    assert repeated.refreshed == 1
    assert alert["occurrence_count"] == 2
    assert alert["due_at"]
    assert alert["sla_state"] == "within_sla"

    with pytest.raises(ValueError, match="resolution note"):
        operations_store.update_operation_alert(
            alert["id"], actor_role="operator", status="resolved"
        )

    resolved = operations_store.update_operation_alert(
        alert["id"],
        actor_role="operator",
        status="resolved",
        assigned_to="Network Operations",
        resolution_note="Asset approved by the service owner.",
    )
    assert resolved["status"] == "resolved"
    assert resolved["assigned_to"] == "Network Operations"
    assert resolved["resolved_at"]
    assert resolved["sla_state"] == "resolved"

    recurrence = operations_store.create_alerts_for_changes(repeated_change)
    assert recurrence.created == 1
    assert operations_store.alert_counts()["resolved"] == 1
    assert operations_store.alert_counts()["open"] == 1


def test_active_maintenance_window_pauses_due_policy_until_disabled(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    policy = operations_store.create_scan_policy(
        name="HQ approved baseline",
        cidr="10.30.0.0/24",
        interval_minutes=60,
        enabled=True,
        authorized_by="admin",
    )
    window = operations_store.create_maintenance_window(
        name="Firewall change",
        starts_at="2026-07-15T10:00:00+00:00",
        ends_at="2026-07-15T12:00:00+00:00",
        reason="CHG-1042",
        policy_id=policy["id"],
        enabled=True,
        created_by="admin",
    )

    claimed = operations_store.claim_due_scan_policies(now="2026-07-15T11:00:00+00:00", limit=1)
    active = operations_store.policy_maintenance_windows(
        policy["id"], now="2026-07-15T11:00:00+00:00"
    )

    assert claimed == []
    assert active[0]["id"] == window["id"]
    assert active[0]["active"] is True

    operations_store.set_maintenance_window_enabled(window["id"], enabled=False)
    claimed_after_disable = operations_store.claim_due_scan_policies(
        now="2099-01-01T00:00:00+00:00", limit=1
    )
    assert [item["id"] for item in claimed_after_disable] == [policy["id"]]


def test_maintenance_windows_reject_unsafe_time_ranges(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="timezone"):
        operations_store.create_maintenance_window(
            name="Missing timezone",
            starts_at="2026-07-15T10:00:00",
            ends_at="2026-07-15T12:00:00",
            reason="test",
            policy_id=None,
            enabled=True,
            created_by="admin",
        )
    with pytest.raises(ValueError, match="31 days"):
        operations_store.create_maintenance_window(
            name="Unsafe duration",
            starts_at="2026-07-01T10:00:00+00:00",
            ends_at="2026-09-01T10:00:00+00:00",
            reason="test",
            policy_id=None,
            enabled=True,
            created_by="admin",
        )


def test_v3_alert_schema_migrates_to_case_workflow(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.execute(
            "CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, "
            "scan_type TEXT NOT NULL, target TEXT NOT NULL, summary TEXT NOT NULL, "
            "status TEXT NOT NULL DEFAULT 'completed')"
        )
        conn.execute("""
            CREATE TABLE operation_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                target TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'acknowledged')),
                scan_run_id INTEGER,
                acknowledged_at TEXT NOT NULL DEFAULT '',
                acknowledged_by TEXT NOT NULL DEFAULT ''
            )
            """)
        conn.execute(
            """
            INSERT INTO operation_alerts (
                created_at, severity, category, title, target, status
            ) VALUES (?, 'High', 'new_asset', 'Legacy alert', '192.168.9.9', 'open')
            """,
            ("2026-07-14T10:00:00+00:00",),
        )

    inventory_store.init_db()
    alerts = operations_store.recent_alerts()

    assert alerts[0]["title"] == "Legacy alert"
    assert alerts[0]["occurrence_count"] == 1
    assert alerts[0]["due_at"] == "2026-07-15T10:00:00+00:00"
    resolved = operations_store.update_operation_alert(
        alerts[0]["id"],
        actor_role="operator",
        status="resolved",
        resolution_note="Legacy alert reviewed and closed.",
    )
    assert resolved["status"] == "resolved"
