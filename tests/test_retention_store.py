from __future__ import annotations

from datetime import datetime, timedelta, timezone

import inventory_store
import retention_store


def _use_temporary_database(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def test_retention_status_exposes_aggregate_tables_without_private_rows(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.init_db()

    result = retention_store.retention_status()
    tables = {row["table"]: row for row in result["tables"]}

    assert "audit_log" in tables
    assert "service_findings" in tables
    assert result["audit_protection"].startswith("The retention endpoint never deletes")
    assert tables["audit_log"]["count"] == 0


def test_retention_cleanup_is_dry_run_first_and_preserves_audit(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    old = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat(timespec="seconds")
    with inventory_store._connect() as conn:
        inventory_store.init_db()
        conn.execute(
            "INSERT INTO scan_runs (created_at, scan_type, target, summary, status) "
            "VALUES (?, 'network', '192.168.1.0/30', 'old', 'completed')",
            (old,),
        )
        scan_run_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            "INSERT INTO network_observations "
            "(scan_run_id, ip_address, observed, status, details) VALUES (?, ?, 1, 'Online', '')",
            (scan_run_id, "192.168.1.1"),
        )
        conn.execute(
            "INSERT INTO audit_log "
            "(created_at, actor_role, action, target, outcome, details) "
            "VALUES (?, 'admin', 'test', 'retention', 'completed', '')",
            (old,),
        )

    preview = retention_store.cleanup_retention(older_than_days=90, dry_run=True, max_rows=100)
    assert preview["dry_run"] is True
    assert preview["eligible"]["network_observations"] == 1
    assert preview["total"] == 0

    cleaned = retention_store.cleanup_retention(older_than_days=90, dry_run=False, max_rows=100)
    assert cleaned["deleted"]["network_observations"] == 1
    with inventory_store._connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM network_observations").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1


def test_retention_cleanup_caps_requested_rows(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.init_db()
    result = retention_store.cleanup_retention(older_than_days=1, dry_run=True, max_rows=999_999)
    assert result["max_rows"] == retention_store.RETENTION_MAX_DELETE_ROWS
