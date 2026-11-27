"""Keep enterprise recovery instructions aligned with the runtime SQLite schema."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import inventory_store


def test_enterprise_recovery_guide_matches_runtime_schema(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    inventory_store.init_db()

    with sqlite3.connect(inventory_store.DB_FILE) as connection:
        runtime_schema = connection.execute("PRAGMA user_version").fetchone()[0]

    guide = (
        Path(__file__).resolve().parents[1] / "docs" / "enterprise-deployment.md"
    ).read_text(encoding="utf-8")

    expected_schema = re.search(r"--expected-schema\s+(\d+)", guide)
    documented_migration = re.search(
        r"schema tracking to version\s+(\d+)", guide
    )

    assert expected_schema is not None
    assert documented_migration is not None
    assert int(expected_schema.group(1)) == runtime_schema
    assert int(documented_migration.group(1)) == runtime_schema
