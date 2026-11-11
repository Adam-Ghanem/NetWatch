"""Regression: recovered standalone evidence must remain immutable to read-only consumers.

Run: python -m pytest -q tests/test_backup_recovered_readonly.py
This is an isolated synthetic SQLite check, not an authenticated application restore.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing

import pytest

import inventory_store
from scripts.verify_sqlite_backup import verify


def test_recovered_snapshot_rejects_consumer_writes_after_source_loss(tmp_path, monkeypatch):
    data_dir = tmp_path / "source"
    source = data_dir / "netwatch.db"
    snapshot = tmp_path / "recovered.sqlite3"
    monkeypatch.setattr(inventory_store, "DATA_DIR", data_dir)
    monkeypatch.setattr(inventory_store, "DB_FILE", source)
    inventory_store.init_db()

    with closing(sqlite3.connect(source)) as live:
        live.execute(
            "INSERT INTO assets (ip_address, first_seen, last_seen, status) VALUES (?, ?, ?, ?)",
            ("192.0.2.42", "2026-01-01", "2026-01-01", "Online"),
        )
        live.commit()
        with closing(sqlite3.connect(snapshot)) as destination:
            live.backup(destination)
            assert destination.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"

    data_dir.rename(tmp_path / "lost-source")
    assert not source.exists()
    sealed = snapshot.read_bytes()
    digest = hashlib.sha256(sealed).hexdigest()
    report = verify(snapshot, expected_schema=11, expected_sha256=digest)
    assert report["read_only"] is True

    with closing(sqlite3.connect(f"{snapshot.as_uri()}?mode=ro", uri=True)) as recovered:
        recovered.execute("PRAGMA query_only=ON")
        query = "SELECT ip_address FROM assets WHERE ip_address = ?"
        row = recovered.execute(query, ("192.0.2.42",))
        assert row.fetchone() == ("192.0.2.42",)
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            recovered.execute("DELETE FROM assets WHERE ip_address = ?", ("192.0.2.42",))

    assert snapshot.read_bytes() == sealed
    sidecars = ("-wal", "-shm", "-journal")
    assert all(not (tmp_path / f"recovered.sqlite3{suffix}").exists() for suffix in sidecars)
