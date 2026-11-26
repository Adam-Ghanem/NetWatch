"""Read-only audit of legacy enterprise queue error text in an offline SQLite copy."""

from __future__ import annotations

import argparse
import json
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from typing import Sequence

from enterprise_store import SAFE_WORKER_ERROR_CODES

_QUEUE_TABLES = ("enterprise_jobs", "enterprise_outbox")
_ERROR_CODES = tuple(sorted(SAFE_WORKER_ERROR_CODES))
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class AuditFailure(RuntimeError):
    """An audit failure with a fixed, non-sensitive diagnostic code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def audit_database(path: Path) -> dict[str, object]:
    """Count legacy free-form queue errors without returning or changing their values."""
    try:
        file_stat = path.lstat()
    except OSError:
        raise AuditFailure("database_unavailable") from None
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size <= 0:
        raise AuditFailure("unsafe_database_file")

    for suffix in _SIDECAR_SUFFIXES:
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists() or sidecar.is_symlink():
            raise AuditFailure("sqlite_sidecar_present")

    try:
        resolved = path.resolve(strict=True)
        uri = f"{resolved.as_uri()}?mode=ro&immutable=1"
        with closing(sqlite3.connect(uri, uri=True, timeout=5.0)) as connection:
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            if not set(_QUEUE_TABLES).issubset(tables):
                raise AuditFailure("enterprise_queue_schema_missing")

            report: dict[str, dict[str, int]] = {}
            placeholders = ", ".join("?" for _ in _ERROR_CODES)
            for table in _QUEUE_TABLES:
                columns = {
                    str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
                }
                if "last_error" not in columns:
                    raise AuditFailure("enterprise_queue_schema_invalid")
                row = connection.execute(
                    f"""
                    SELECT
                        COUNT(*) AS row_count,
                        SUM(
                            CASE
                                WHEN last_error IS NULL
                                  OR (last_error <> '' AND last_error NOT IN ({placeholders}))
                                THEN 1 ELSE 0
                            END
                        ) AS legacy_count
                    FROM {table}
                    """,
                    _ERROR_CODES,
                ).fetchone()
                report[table] = {
                    "rows": int(row[0] or 0),
                    "legacy_error_rows": int(row[1] or 0),
                }
    except AuditFailure:
        raise
    except (OSError, sqlite3.Error, ValueError):
        raise AuditFailure("database_unreadable") from None

    try:
        final_stat = path.lstat()
    except OSError:
        raise AuditFailure("database_changed_during_audit") from None
    initial_identity = (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_mode,
        file_stat.st_size,
        file_stat.st_mtime_ns,
    )
    final_identity = (
        final_stat.st_dev,
        final_stat.st_ino,
        final_stat.st_mode,
        final_stat.st_size,
        final_stat.st_mtime_ns,
    )
    if initial_identity != final_identity:
        raise AuditFailure("database_changed_during_audit")
    for suffix in _SIDECAR_SUFFIXES:
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists() or sidecar.is_symlink():
            raise AuditFailure("sqlite_sidecar_present")

    legacy_total = sum(item["legacy_error_rows"] for item in report.values())
    return {
        "ok": legacy_total == 0,
        "legacy_error_rows": legacy_total,
        "tables": report,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only audit of legacy enterprise queue error fields in an offline SQLite copy."
        )
    )
    parser.add_argument("database", type=Path, help="standalone offline SQLite copy")
    args = parser.parse_args(argv)

    try:
        result = audit_database(args.database)
    except AuditFailure as exc:
        print(json.dumps({"ok": False, "error_code": exc.code}, sort_keys=True))
        return 2

    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
