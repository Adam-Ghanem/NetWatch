"""Fail closed on a valid-but-tampered recovered SQLite snapshot.

Run: python -m pytest -q tests/test_backup_recovered_tamper.py
Synthetic local data only; this is not an authenticated application restore.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing

import pytest

import inventory_store
from scripts.verify_sqlite_backup import verify


def test_recovered_snapshot_rejects_valid_sqlite_content_tamper(tmp_path, monkeypatch):
    data_dir = tmp_path / "source"
    source = data_dir / "netwatch.db"
    snapshot = tmp_path / "recovered.sqlite3"
    monkeypatch.setattr(inventory_store, "DATA_DIR", data_dir)
    monkeypatch.setattr(inventory_store, "DB_FILE", source)
    inventory_store.init_db()

    with closing(sqlite3.connect(source)) as live:
        live.execute(
            "INSERT INTO assets (ip_address, first_seen, last_seen, status) VALUES (?, ?, ?, ?)",
            ("192.0.2.50", "2026-01-01", "2026-01-01", "Online"),
        )
        live.commit()
        with closing(sqlite3.connect(snapshot)) as destination:
            live.backup(destination)
            assert destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"

    trusted_digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    data_dir.rename(tmp_path / "lost-source")
    assert not source.exists()
    assert verify(snapshot, expected_schema=11, expected_sha256=trusted_digest)["read_only"]

    # The attacker changes a legitimate row, keeping SQLite and FK integrity valid.
    with closing(sqlite3.connect(snapshot)) as tamper:
        tamper.execute(
            "UPDATE assets SET status = ? WHERE ip_address = ?",
            ("Offline", "192.0.2.50"),
        )
        tamper.commit()

    tampered_bytes = snapshot.read_bytes()
    assert hashlib.sha256(tampered_bytes).hexdigest() != trusted_digest
    with pytest.raises(ValueError, match="SHA-256 does not match"):
        verify(snapshot, expected_schema=11, expected_sha256=trusted_digest)
    assert snapshot.read_bytes() == tampered_bytes
    assert all(
        not (tmp_path / f"recovered.sqlite3{suffix}").exists()
        for suffix in ("-wal", "-shm", "-journal")
    )
