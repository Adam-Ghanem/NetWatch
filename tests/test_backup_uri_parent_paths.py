"""Regression: SQLite URI escaping must preserve parent directory components."""

from __future__ import annotations

import sqlite3
from contextlib import closing

import pytest

import inventory_store
from scripts.verify_sqlite_backup import verify


@pytest.mark.parametrize(
    "directory",
    [
        "archive#2026",
        "archive?mode=rw",
        "archive%23literal",
        "archive space",
        "archive-évidence",
    ],
)
def test_offline_backup_verifies_exact_parent_directory(tmp_path, monkeypatch, directory):
    """Read only the requested snapshot, even with URI-sensitive parent paths."""
    data_dir = tmp_path / "runtime"
    source = data_dir / "netwatch.db"
    snapshot_dir = tmp_path / directory
    snapshot_dir.mkdir()
    snapshot = snapshot_dir / "snapshot.sqlite3"
    monkeypatch.setattr(inventory_store, "DATA_DIR", data_dir)
    monkeypatch.setattr(inventory_store, "DB_FILE", source)
    inventory_store.init_db()

    with closing(sqlite3.connect(source)) as live:
        with closing(sqlite3.connect(snapshot)) as destination:
            live.backup(destination)
            assert destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"

    original = snapshot.read_bytes()
    report = verify(snapshot, expected_schema=11)

    assert report["path"] == str(snapshot.resolve())
    assert report["integrity"] == "ok"
    assert report["schema_version"] == 11
    assert report["read_only"] is True
    assert snapshot.read_bytes() == original
