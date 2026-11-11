"""Source-loss recovery must reject a corrupted SQLite header, even with a matching digest.

Run: python -m pytest -q tests/test_backup_recovered_corrupt_header.py
Uses only synthetic local inventory and no network access.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing

import pytest

import inventory_store
from scripts.verify_sqlite_backup import verify


def test_recovered_snapshot_rejects_corrupt_header_with_matching_digest(tmp_path, monkeypatch):
    data_dir = tmp_path / "source"
    source = data_dir / "netwatch.db"
    snapshot = tmp_path / "recovered.sqlite3"
    monkeypatch.setattr(inventory_store, "DATA_DIR", data_dir)
    monkeypatch.setattr(inventory_store, "DB_FILE", source)
    inventory_store.init_db()

    with closing(sqlite3.connect(source)) as live:
        live.execute(
            "INSERT INTO assets (ip_address, first_seen, last_seen, status) "
            "VALUES (?, ?, ?, ?)",
            ("192.0.2.60", "2026-01-01", "2026-01-01", "Online"),
        )
        live.commit()
        with closing(sqlite3.connect(snapshot)) as destination:
            live.backup(destination)
            journal_mode = destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            assert journal_mode == "delete"

    original = snapshot.read_bytes()
    assert verify(
        snapshot, expected_schema=11, expected_sha256=hashlib.sha256(original).hexdigest()
    )["read_only"]

    data_dir.rename(tmp_path / "lost-source")
    assert not source.exists()

    # A digest can authenticate bytes only against a trusted external reference.
    # Even a matching digest of corrupt bytes must never bypass SQLite validation.
    corrupted = b"NOT SQLite!" + original[len(b"NOT SQLite!") :]
    snapshot.write_bytes(corrupted)
    assert len(corrupted) == len(original)
    with pytest.raises((sqlite3.DatabaseError, ValueError)):
        verify(
            snapshot,
            expected_schema=11,
            expected_sha256=hashlib.sha256(corrupted).hexdigest(),
        )

    assert snapshot.read_bytes() == corrupted
    sidecars = ("-wal", "-shm", "-journal")
    assert all(not (tmp_path / f"recovered.sqlite3{suffix}").exists() for suffix in sidecars)
