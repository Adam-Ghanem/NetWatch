"""Regression tests for offline backup sidecar isolation."""

from __future__ import annotations

import sqlite3

import pytest

from scripts.verify_sqlite_backup import TABLES, verify


def _snapshot(path):
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 10")
        for table in TABLES:
            connection.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)")


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_verifier_rejects_sqlite_sidecar_files(tmp_path, suffix):
    path = tmp_path / "snapshot.sqlite3"
    _snapshot(path)
    sidecar = tmp_path / f"snapshot.sqlite3{suffix}"
    sidecar.write_bytes(b"untrusted sidecar")

    with pytest.raises(ValueError, match="SQLite sidecar files"):
        verify(path, expected_schema=10)


def test_verifier_rejects_live_wal_snapshot_even_if_main_file_is_valid(tmp_path):
    path = tmp_path / "snapshot.sqlite3"
    _snapshot(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA wal_autocheckpoint = 0")
        connection.execute("INSERT INTO assets DEFAULT VALUES")
        connection.commit()
        assert (tmp_path / "snapshot.sqlite3-wal").exists()

        with pytest.raises(ValueError, match="SQLite sidecar files"):
            verify(path, expected_schema=10)
    finally:
        connection.close()


def test_verifier_accepts_standalone_snapshot_after_sidecars_removed(tmp_path):
    path = tmp_path / "snapshot.sqlite3"
    _snapshot(path)

    report = verify(path, expected_schema=10)

    assert report["read_only"] is True
    assert report["integrity"] == "ok"
