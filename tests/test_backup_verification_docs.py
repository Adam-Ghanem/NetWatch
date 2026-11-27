"""Keep backup verification examples aligned with the runtime SQLite schema."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import inventory_store


def test_backup_verification_runbook_matches_runtime_schema(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    inventory_store.init_db()

    with sqlite3.connect(inventory_store.DB_FILE) as connection:
        runtime_schema = connection.execute("PRAGMA user_version").fetchone()[0]

    guide_path = Path(__file__).resolve().parents[1] / "docs" / "backup-verification.md"
    guide = guide_path.read_text(encoding="utf-8")
    documented_schemas = re.findall(r"--expected-schema\s+(\d+)", guide)

    assert len(documented_schemas) == 2
    assert all(int(schema) == runtime_schema for schema in documented_schemas)
