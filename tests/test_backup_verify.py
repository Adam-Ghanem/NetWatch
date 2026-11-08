from __future__ import annotations

import hashlib
import os
import sqlite3

import pytest

import scripts.verify_sqlite_backup as backup_verifier
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
            elif table == "assets":
                connection.execute("CREATE TABLE assets (id INTEGER PRIMARY KEY, ip_address TEXT)")
            elif table == "scan_runs":
                connection.execute("CREATE TABLE scan_runs (id INTEGER PRIMARY KEY, created_at TEXT)")
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


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_backup_verification_rejects_sqlite_sidecars(tmp_path, suffix):
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    sidecar = tmp_path / f"backup.sqlite3{suffix}"
    sidecar.write_bytes(b"sidecar marker")

    with pytest.raises(ValueError, match="sidecar files"):
        verify(path, expected_schema=10)

    assert sidecar.read_bytes() == b"sidecar marker"


def test_backup_verification_rejects_symlink(tmp_path):
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    alias = tmp_path / "backup-alias.sqlite3"
    try:
        alias.symlink_to(path)
    except (NotImplementedError, OSError):
        pytest.skip("Symbolic links are unavailable on this platform")

    with pytest.raises(ValueError, match="symbolic link"):
        verify(alias, expected_schema=10)


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_backup_verification_rejects_dangling_sidecar_symlinks(tmp_path, suffix):
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    sidecar = tmp_path / f"backup.sqlite3{suffix}"
    try:
        sidecar.symlink_to(tmp_path / "nonexistent-sidecar")
    except (NotImplementedError, OSError):
        pytest.skip("Symbolic links are unavailable on this platform")

    assert sidecar.is_symlink()
    assert not sidecar.exists()
    with pytest.raises(ValueError, match="sidecar files"):
        verify(path, expected_schema=10)


def test_backup_rejects_same_metadata_content_mutation(tmp_path, monkeypatch):
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    original_stat = path.stat()
    original_hash = backup_verifier._file_sha256
    calls = 0

    def hash_with_mutation(candidate):
        nonlocal calls
        calls += 1
        if calls == 2:
            with candidate.open("r+b") as backup:
                backup.seek(100)
                original_byte = backup.read(1)
                backup.seek(100)
                backup.write(bytes([original_byte[0] ^ 1]))
            os.utime(candidate, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
        return original_hash(candidate)

    monkeypatch.setattr(backup_verifier, "_file_sha256", hash_with_mutation)
    with pytest.raises(ValueError, match="content changed"):
        verify(path, expected_schema=10)
    assert calls == 2
    assert path.stat().st_size == original_stat.st_size
    assert path.stat().st_mtime_ns == original_stat.st_mtime_ns


def test_backup_rejects_same_content_file_replacement(tmp_path, monkeypatch):
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    original = path.stat()
    require_standalone = backup_verifier._require_standalone
    calls = 0

    def replace_after_sqlite_checks(candidate):
        nonlocal calls
        calls += 1
        require_standalone(candidate)
        if calls == 2:
            replacement = tmp_path / "replacement.sqlite3"
            replacement.write_bytes(path.read_bytes())
            os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
            os.replace(replacement, path)

    monkeypatch.setattr(backup_verifier, "_require_standalone", replace_after_sqlite_checks)
    with pytest.raises(ValueError, match="identity changed"):
        verify(path, expected_schema=10)
    assert calls == 2
    assert path.stat().st_size == original.st_size
    assert path.stat().st_mtime_ns == original.st_mtime_ns


def test_backup_verification_rejects_hardlinked_snapshot(tmp_path):
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    alias = tmp_path / "linked.sqlite3"
    try:
        os.link(path, alias)
    except (NotImplementedError, OSError):
        pytest.skip("Hard links are unavailable on this filesystem")

    with pytest.raises(ValueError, match="hard links"):
        verify(path, expected_schema=10)
    with pytest.raises(ValueError, match="hard links"):
        verify(alias, expected_schema=10)
    assert path.stat().st_nlink == 2


def test_backup_verification_accepts_independent_copy(tmp_path):
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    copy = tmp_path / "independent.sqlite3"
    copy.write_bytes(path.read_bytes())

    assert verify(copy, expected_schema=10)["integrity"] == "ok"


def test_backup_rejects_missing_runtime_columns(tmp_path):
    path = tmp_path / "missing-columns.sqlite3"
    _backup(path)
    with sqlite3.connect(path) as connection:
        connection.execute("ALTER TABLE assets DROP COLUMN ip_address")

    with pytest.raises(ValueError, match="assets: ip_address"):
        verify(path, expected_schema=10)


def test_backup_rejects_missing_scan_timestamp(tmp_path):
    path = tmp_path / "missing-timestamp.sqlite3"
    _backup(path)
    with sqlite3.connect(path) as connection:
        connection.execute("ALTER TABLE scan_runs DROP COLUMN created_at")

    with pytest.raises(ValueError, match="scan_runs: created_at"):
        verify(path, expected_schema=10)
