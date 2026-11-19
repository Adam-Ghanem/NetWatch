from __future__ import annotations

import hashlib
import sqlite3

import pytest

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

    monkeypatch.setattr("scripts.verify_sqlite_backup._file_sha256", changing_digest)
    with pytest.raises(ValueError, match="content changed during verification"):
        verify(path, expected_sha256=original_hash)
    assert calls == [path, path]


def test_backup_verification_detects_real_byte_mutation_with_restored_metadata(
    tmp_path, monkeypatch
):
    """The second digest must read bytes, not trust unchanged stat metadata."""
    import os

    from scripts import verify_sqlite_backup

    path = tmp_path / "backup.sqlite3"
    _backup(path)
    original = path.read_bytes()
    before = path.stat()
    original_hash = hashlib.sha256(original).hexdigest()
    real_hash = verify_sqlite_backup._file_sha256
    calls = 0

    def mutate_before_final_hash(snapshot):
        nonlocal calls
        calls += 1
        if calls == 2:
            changed = bytearray(original)
            changed[-1] ^= 1
            path.write_bytes(changed)
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            assert (path.stat().st_size, path.stat().st_mtime_ns) == (
                before.st_size,
                before.st_mtime_ns,
            )
        return real_hash(snapshot)

    monkeypatch.setattr(verify_sqlite_backup, "_file_sha256", mutate_before_final_hash)
    with pytest.raises(ValueError, match="content changed during verification"):
        verify(path, expected_sha256=original_hash)
    assert calls == 2
    assert path.read_bytes() != original


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_backup_verification_rejects_sqlite_sidecars(tmp_path, suffix):
    """Any adjacent sidecar means main-file-only hashing is insufficient."""
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    sidecar = path.with_name(path.name + suffix)
    sidecar.write_bytes(b"untrusted sidecar")
    with pytest.raises(ValueError, match="SQLite sidecar files"):
        verify(path, expected_schema=10)


def test_backup_verification_rejects_uncheckpointed_wal(tmp_path):
    """Reject a real WAL with committed data absent from the main file."""
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        connection.execute("PRAGMA wal_autocheckpoint=0")
        connection.execute("INSERT INTO assets DEFAULT VALUES")
        connection.commit()
        assert path.with_name(path.name + "-wal").exists()
        with pytest.raises(ValueError, match="SQLite sidecar files"):
            verify(path, expected_schema=10)
    finally:
        connection.close()


def test_backup_verification_accepts_standalone_snapshot_after_wal_close(tmp_path):
    """A clean standalone database remains valid after WAL checkpointing."""
    path = tmp_path / "backup.sqlite3"
    _backup(path)
    # sqlite3.Connection context managers commit/rollback but do not close.
    # Close explicitly so SQLite can checkpoint and remove the WAL sidecar.
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("INSERT INTO assets DEFAULT VALUES")
        connection.commit()
    finally:
        connection.close()
    assert not path.with_name(path.name + "-wal").exists()
    report = verify(path, expected_schema=10)
    assert report["counts"]["assets"] == 2
