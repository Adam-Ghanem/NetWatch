"""Regression: an offline backup must recover linked inventory evidence, not just tables."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing

import inventory_store
from scripts.verify_sqlite_backup import verify


def test_offline_snapshot_restores_linked_inventory_evidence(tmp_path, monkeypatch):
    data_dir = tmp_path / "live"
    source = data_dir / "netwatch.db"
    snapshot = tmp_path / "standalone.sqlite3"
    monkeypatch.setattr(inventory_store, "DATA_DIR", data_dir)
    monkeypatch.setattr(inventory_store, "DB_FILE", source)
    inventory_store.init_db()

    # Synthetic, explicitly authorized test evidence; no capture or scanning.
    with closing(sqlite3.connect(source)) as live:
        live.execute(
            "INSERT INTO assets (ip_address, first_seen, last_seen, status) "
            "VALUES (?, ?, ?, ?)",
            ("192.0.2.10", "2026-01-01", "2026-01-01", "Online"),
        )
        cursor = live.execute(
            "INSERT INTO scan_runs (created_at, scan_type, target, summary, status) "
            "VALUES (?, ?, ?, ?, ?)",
            ("2026-01-01", "offline-test", "192.0.2.0/24", "synthetic", "completed"),
        )
        scan_id = cursor.lastrowid
        live.execute(
            "INSERT INTO network_observations "
            "(scan_run_id, ip_address, observed, status) VALUES (?, ?, ?, ?)",
            (scan_id, "192.0.2.10", 1, "Online"),
        )
        live.commit()
        with closing(sqlite3.connect(snapshot)) as destination:
            live.backup(destination)
            journal_mode = destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            assert journal_mode == "delete"

    original = snapshot.read_bytes()
    report = verify(
        snapshot,
        expected_schema=11,
        expected_sha256=hashlib.sha256(original).hexdigest(),
    )
    assert report["counts"]["assets"] == 1
    assert report["counts"]["scan_runs"] == 1
    assert report["counts"]["network_observations"] == 1

    # Independent read-only connection simulates the recovered evidence consumer.
    with closing(sqlite3.connect(f"{snapshot.as_uri()}?mode=ro", uri=True)) as restored:
        restored.execute("PRAGMA query_only=ON")
        rows = restored.execute(
            "SELECT a.ip_address, n.observed, s.scan_type "
            "FROM network_observations AS n "
            "JOIN assets AS a ON a.ip_address = n.ip_address "
            "JOIN scan_runs AS s ON s.id = n.scan_run_id"
        ).fetchall()
        assert rows == [("192.0.2.10", 1, "offline-test")]
        assert restored.execute("PRAGMA foreign_key_check").fetchone() is None

    assert snapshot.read_bytes() == original
    sidecars = [
        tmp_path / f"standalone.sqlite3{suffix}"
        for suffix in ("-wal", "-shm", "-journal")
    ]
    assert all(not sidecar.exists() for sidecar in sidecars)
