"""Offline recovery smoke test against the real initialized NetWatch schema."""

from __future__ import annotations

import sqlite3
from contextlib import closing

import inventory_store
from scripts.verify_sqlite_backup import verify


def test_runtime_schema_snapshot_can_be_opened_and_verified(tmp_path, monkeypatch):
    """Exercise a consistent SQLite backup, not a hand-written test schema."""
    data_dir = tmp_path / "runtime"
    source = data_dir / "netwatch.db"
    snapshot = tmp_path / "offline-snapshot.sqlite3"
    monkeypatch.setattr(inventory_store, "DATA_DIR", data_dir)
    monkeypatch.setattr(inventory_store, "DB_FILE", source)

    inventory_store.init_db()
    # SQLite connection context managers commit/rollback but do not close handles.
    # Close both before verification; the backup inherits the source WAL mode.
    with closing(sqlite3.connect(source)) as live:
        with closing(sqlite3.connect(snapshot)) as destination:
            live.backup(destination)
            # A WAL-mode backup is not standalone until its journal is normalized.
            # Switch the isolated destination to DELETE mode before closing it.
            assert destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"

    before = snapshot.read_bytes()
    report = verify(snapshot, expected_schema=11)
    assert report["schema_version"] == 11
    assert report["integrity"] == "ok"
    assert report["read_only"] is True
    assert snapshot.read_bytes() == before

    # Prove the snapshot is actually usable by a fresh SQLite connection.
    with closing(sqlite3.connect(f"{snapshot.as_uri()}?mode=ro", uri=True)) as restored:
        restored.execute("PRAGMA query_only = ON")
        assert restored.execute("PRAGMA user_version").fetchone()[0] == 11
        assert restored.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 0
