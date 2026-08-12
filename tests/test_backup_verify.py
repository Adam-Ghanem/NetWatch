from __future__ import annotations

import sqlite3

import pytest

from scripts.verify_sqlite_backup import verify


def test_backup_verification_is_read_only_and_checks_schema(tmp_path):
    path = tmp_path / "backup.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 10")
        connection.execute("CREATE TABLE assets (id INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO assets DEFAULT VALUES")

    report = verify(path, expected_schema=10)
    assert report["integrity"] == "ok"
    assert report["schema_version"] == 10
    counts = report["counts"]
    assert isinstance(counts, dict)
    assert counts["assets"] == 1
    assert report["read_only"] is True


def test_backup_verification_rejects_empty_or_wrong_schema(tmp_path):
    empty = tmp_path / "empty.sqlite3"
    empty.touch()
    with pytest.raises(ValueError, match="missing or empty"):
        verify(empty)

    path = tmp_path / "backup.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 9")
    with pytest.raises(ValueError, match="Expected schema 10"):
        verify(path, expected_schema=10)
