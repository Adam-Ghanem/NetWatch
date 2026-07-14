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

    assert operations_store.create_alerts_for_changes(missing) == 1
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
    assert version == 4
