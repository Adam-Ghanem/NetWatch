"""Regression: rejected offline evidence must not touch a live WAL source."""

from __future__ import annotations

import sqlite3

import pytest

from scripts.verify_sqlite_backup import TABLES, verify


def test_rejected_offline_snapshot_does_not_mutate_live_wal(tmp_path):
    source = tmp_path / "live.sqlite3"
    snapshot = tmp_path / "offline.sqlite3"
    with sqlite3.connect(source) as setup:
        setup.execute("PRAGMA user_version=10")
        for table in TABLES:
            setup.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)")
        setup.execute("INSERT INTO assets DEFAULT VALUES")

    connection = sqlite3.connect(source)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("INSERT INTO assets DEFAULT VALUES")
        connection.commit()
        wal = source.with_name(source.name + "-wal")
        before = wal.read_bytes()
        assert before

        destination = sqlite3.connect(snapshot)
        try:
            connection.backup(destination)
            assert destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
        finally:
            destination.close()

        with pytest.raises(ValueError, match="does not match"):
            verify(snapshot, expected_schema=10, expected_sha256="0" * 64)

        assert wal.read_bytes() == before
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 2
        assert not any(
            snapshot.with_name(snapshot.name + suffix).exists()
            for suffix in ("-wal", "-shm", "-journal")
        )
    finally:
        connection.close()
