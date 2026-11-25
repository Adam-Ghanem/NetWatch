from __future__ import annotations

import hashlib
import os
import sqlite3

import pytest

import scripts.verify_sqlite_backup as backup_verifier


def _backup(path):
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 10")
        for table in backup_verifier.TABLES:
            if table == "operation_alerts":
                connection.execute(
                    "CREATE TABLE operation_alerts ("
                    "id INTEGER PRIMARY KEY, asset_id INTEGER REFERENCES assets(id))"
                )
            else:
                connection.execute(f"CREATE TABLE {table} (id INTEGER PRIMARY KEY)")
        connection.execute("INSERT INTO assets DEFAULT VALUES")


def test_backup_verification_rejects_symlinked_input(tmp_path):
    target = tmp_path / "backup.sqlite3"
    _backup(target)
    link = tmp_path / "backup-link.sqlite3"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("Symlink creation is unavailable on this platform.")
    with pytest.raises(ValueError, match="regular file"):
        backup_verifier.verify(link)


def test_backup_verification_rejects_source_replacement_during_sqlite_check(
    tmp_path, monkeypatch
):
    path = tmp_path / "backup.sqlite3"
    replacement = tmp_path / "replacement.sqlite3"
    _backup(path)
    _backup(replacement)
    original_bytes = path.read_bytes()
    expected_hash = hashlib.sha256(original_bytes).hexdigest()
    original_stat = path.stat()
    with sqlite3.connect(replacement) as connection:
        connection.execute("UPDATE assets SET id = 2 WHERE id = 1")
    assert replacement.stat().st_size == original_stat.st_size
    os.utime(replacement, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))

    real_connect = backup_verifier.sqlite3.connect
    opened_uris = []

    def replace_source_before_connect(database, *args, **kwargs):
        opened_uris.append(database)
        os.replace(replacement, path)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(backup_verifier.sqlite3, "connect", replace_source_before_connect)
    with pytest.raises(ValueError, match="changed during verification"):
        backup_verifier.verify(path, expected_schema=10, expected_sha256=expected_hash)
    assert len(opened_uris) == 1
    assert path.resolve().as_uri() not in opened_uris[0]
