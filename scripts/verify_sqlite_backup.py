#!/usr/bin/env python3
"""Verify a NetWatch SQLite backup without modifying it."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path

TABLES = (
    "assets",
    "scan_runs",
    "network_observations",
    "audit_log",
    "operation_alerts",
    "service_findings",
)


def verify(path: Path, expected_schema: int | None = None) -> dict[str, object]:
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("Backup file is missing or empty.")
    uri = f"file:{path.resolve()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        integrity = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
        schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if integrity.lower() != "ok":
            raise ValueError(f"SQLite integrity check failed: {integrity}")
        if expected_schema is not None and schema != expected_schema:
            raise ValueError(f"Expected schema {expected_schema}, found {schema}.")
        counts: dict[str, int] = {}
        for table in TABLES:
            try:
                counts[table] = int(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                )
            except sqlite3.Error:
                counts[table] = -1
    return {
        "path": str(path.resolve()),
        "bytes": path.stat().st_size,
        "integrity": integrity,
        "schema_version": schema,
        "counts": counts,
        "read_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path)
    parser.add_argument("--expected-schema", type=int, default=None)
    args = parser.parse_args()
    try:
        report = verify(args.backup, args.expected_schema)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2
    print(json.dumps({"ok": True, **report}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
