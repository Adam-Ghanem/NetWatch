from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

from scripts import verify_sqlite_backup as backup_verifier
from scripts.verify_sqlite_backup import TABLES, verify


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


def test_backup_verification_detects_content_change_without_metadata_change(
    tmp_path, monkeypatch
):
    """A replaced same-size snapshot can retain size and mtime."""
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    original_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    calls = []

    def changing_digest(_path):
        calls.append(_path)
        return original_hash if len(calls) == 1 else "f" * 64

    monkeypatch.setattr(backup_verifier, "_file_sha256", changing_digest)
    with pytest.raises(ValueError, match="content changed during verification"):
        verify(path, expected_sha256=original_hash)
    assert calls == [path, path]


def test_backup_verification_uses_hashed_private_snapshot_during_path_swap(
    tmp_path, monkeypatch
):
    """SQLite must never open the mutable source path after it has been hashed."""
    path = tmp_path / "backup.sqlite3"
    replacement = tmp_path / "replacement.sqlite3"
    _backup(path)
    _backup(replacement)
    with sqlite3.connect(replacement) as connection:
        connection.execute("INSERT INTO assets DEFAULT VALUES")

    original_bytes = path.read_bytes()
    replacement_bytes = replacement.read_bytes()
    assert len(original_bytes) == len(replacement_bytes)
    original_hash = hashlib.sha256(original_bytes).hexdigest()
    real_connect = sqlite3.connect
    opened_paths = []
    swaps = []

    def connect_with_path_swap(database, *args, **kwargs):
        uri = str(database)
        target = Path(unquote(urlsplit(uri).path)) if uri.startswith("file:") else Path(uri)
        opened_paths.append(target)
        if target == path.resolve():
            saved_original = tmp_path / "original-held.sqlite3"
            saved_replacement = tmp_path / "replacement-held.sqlite3"
            os.replace(path, saved_original)
            os.replace(replacement, path)
            try:
                connection = real_connect(database, *args, **kwargs)
            finally:
                os.replace(path, saved_replacement)
                os.replace(saved_original, path)
                os.replace(saved_replacement, replacement)
            swaps.append(target)
            return connection
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(backup_verifier.sqlite3, "connect", connect_with_path_swap)

    report = verify(path, expected_schema=10, expected_sha256=original_hash)

    counts = report["counts"]
    assert isinstance(counts, dict)
    assert path.resolve() not in opened_paths
    assert swaps == []
    assert counts["assets"] == 1
    assert report["sha256"] == original_hash
    assert path.read_bytes() == original_bytes
    assert replacement.read_bytes() == replacement_bytes
