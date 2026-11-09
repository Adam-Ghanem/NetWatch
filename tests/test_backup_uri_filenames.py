"""Regression: SQLite URI escaping must not reinterpret backup filenames."""

from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

import inventory_store
from scripts.verify_sqlite_backup import verify


@pytest.mark.parametrize("filename", [
        "snapshot#fragment.sqlite3",
        "snapshot?mode=rw.sqlite3",
        "snapshot%23fragment.sqlite3",
        "snapshot%3Fmode=rw.sqlite3",
    ])
def test_offline_snapshot_with_uri_metacharacters_is_verified(tmp_path, monkeypatch, filename):
    """Verify the actual file, not a truncated URI or query-string target."""
    data_dir = tmp_path / "runtime"
    source = data_dir / "netwatch.db"
    snapshot = tmp_path / filename
    monkeypatch.setattr(inventory_store, "DATA_DIR", data_dir)
    monkeypatch.setattr(inventory_store, "DB_FILE", source)
    inventory_store.init_db()

    with closing(sqlite3.connect(source)) as live:
        with closing(sqlite3.connect(snapshot)) as destination:
            live.backup(destination)
            assert destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"

    before = snapshot.read_bytes()
    report = verify(snapshot, expected_schema=11)
    assert report["path"] == str(snapshot.resolve())
    assert report["integrity"] == "ok"
    assert report["schema_version"] == 11
    assert report["read_only"] is True
    assert snapshot.read_bytes() == before
