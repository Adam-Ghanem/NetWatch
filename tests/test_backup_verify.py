from __future__ import annotations

import hashlib
import json
import sqlite3
import sys

import pytest

from scripts.verify_sqlite_backup import TABLES, main, verify


def _backup(path, *, schema=10):
    with sqlite3.connect(path) as connection:
        connection.execute(f"PRAGMA user_version = {schema}")
        for table in TABLES:
            if table == "operation_alerts":
                connection.execute(
                    "CREATE TABLE operation_alerts ("
                    "id INTEGER PRIMARY KEY, asset_id INTEGER REFERENCES assets(id))"
                )
            else:
                connection.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO assets DEFAULT VALUES")


def test_backup_verification_is_read_only_and_checks_schema(tmp_path):
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    original = path.read_bytes()
    expected_hash = hashlib.sha256(original).hexdigest()

    report = verify(path, expected_schema=10, expected_sha256=expected_hash.upper())

    assert report["integrity"] == "ok"
    assert report["foreign_key_violations"] == 0
    assert report["schema_version"] == 10
    assert report["sha256"] == expected_hash
    assert report["bytes"] == len(original)
    counts = report["counts"]
    assert isinstance(counts, dict)
    assert counts["assets"] == 1
    assert set(counts) == set(TABLES)
    assert report["read_only"] is True
    assert path.read_bytes() == original


def test_backup_verification_rejects_empty_or_wrong_schema(tmp_path):
    empty = tmp_path / "empty.sqlite3"
    empty.touch()
    with pytest.raises(ValueError, match="missing or empty"):
        verify(empty)

    path = tmp_path / "backup.sqlite3"
    _backup(path, schema=9)
    with pytest.raises(ValueError, match="Expected schema 10"):
        verify(path, expected_schema=10)
    with pytest.raises(ValueError, match="positive integer"):
        verify(path, expected_schema=0)


def test_backup_verification_rejects_incomplete_schema(tmp_path):
    path = tmp_path / "incomplete.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 10")
        connection.execute("CREATE TABLE assets (id INTEGER PRIMARY KEY)")

    with pytest.raises(ValueError, match="Missing required NetWatch tables"):
        verify(path, expected_schema=10)


def test_backup_verification_rejects_missing_schema_version(tmp_path):
    path = tmp_path / "unversioned.sqlite3"
    _backup(path, schema=0)

    with pytest.raises(ValueError, match="no NetWatch schema version"):
        verify(path)


def test_backup_verification_rejects_broken_foreign_keys(tmp_path):
    path = tmp_path / "orphan.sqlite3"
    _backup(path)
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO operation_alerts (asset_id) VALUES (999)")

    with pytest.raises(ValueError, match="foreign key violations"):
        verify(path, expected_schema=10)


def test_backup_verification_rejects_mismatched_or_invalid_sha256(tmp_path):
    path = tmp_path / "backup.sqlite3"
    _backup(path)

    with pytest.raises(ValueError, match="does not match"):
        verify(path, expected_sha256="0" * 64)
    with pytest.raises(ValueError, match="64 hexadecimal"):
        verify(path, expected_sha256="bad-digest")


def test_backup_verification_handles_reserved_uri_characters(tmp_path):
    path = tmp_path / "backup?2026#good.sqlite3"
    _backup(path)

    report = verify(path, expected_schema=10)

    assert report["integrity"] == "ok"
    counts = report["counts"]
    assert isinstance(counts, dict)
    assert counts["assets"] == 1


def test_backup_verification_rejects_non_sqlite_data(tmp_path):
    path = tmp_path / "fake.sqlite3"
    path.write_bytes(b"not a SQLite database")

    with pytest.raises(sqlite3.DatabaseError):
        verify(path)



def test_backup_verification_redacts_parent_directory(tmp_path):
    path = tmp_path / "private-volume" / "backup.sqlite3"
    path.parent.mkdir()
    _backup(path)

    report = verify(path)

    assert report["path"] == path.name
    assert str(path.parent) not in str(report["path"])


def test_backup_cli_redacts_filesystem_paths_on_oserror(
    tmp_path, monkeypatch, capsys
):
    path = tmp_path / "backup.sqlite3"
    path.write_bytes(b"placeholder")

    def fail_read(_path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr("scripts.verify_sqlite_backup._file_sha256", fail_read)
    monkeypatch.setattr(sys, "argv", ["verify_sqlite_backup.py", str(path)])

    assert main() == 2
    output = capsys.readouterr().out

    assert str(tmp_path) not in output
    assert json.loads(output) == {
        "ok": False,
        "error": "Unable to access backup file.",
    }
