#!/usr/bin/env python3
"""Strict, read-only verification of an offline NetWatch SQLite backup.

This checks backup structure and transport integrity, not encryption,
off-host rotation, audit HMAC keys, or a successful application restore.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sqlite3
from contextlib import closing
from pathlib import Path

TABLES = (
    "assets",
    "scan_runs",
    "network_observations",
    "audit_log",
    "operation_alerts",
    "service_findings",
)
_HASH_CHUNK_BYTES = 1024 * 1024
# Minimal runtime columns; this is not a complete migration compatibility audit.
REQUIRED_COLUMNS = {
    "assets": ("ip_address",),
    "scan_runs": ("created_at",),
    "network_observations": ("scan_run_id", "ip_address"),
}


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as backup:
        for chunk in iter(lambda: backup.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_digest(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise ValueError("Expected SHA-256 must be exactly 64 hexadecimal characters.")
    return normalized


def _require_standalone(path: Path) -> None:
    """Reject paths that could silently depend on unverified SQLite sidecars."""
    if path.is_symlink():
        raise ValueError("Backup must be a regular file, not a symbolic link.")
    if any(parent.is_symlink() for parent in path.parents):
        raise ValueError("Backup parent directories must not be symbolic links.")
    if path.is_file() and path.stat().st_nlink != 1:
        raise ValueError("Backup must not have hard links; copy a standalone snapshot.")
    if any(
        sidecar.exists() or sidecar.is_symlink()
        for suffix in ("-wal", "-shm", "-journal")
        for sidecar in (Path(f"{path}{suffix}"),)
    ):
        raise ValueError("Backup has SQLite sidecar files; export a standalone snapshot.")


def verify(
    path: Path,
    expected_schema: int | None = None,
    expected_sha256: str | None = None,
) -> dict[str, object]:
    """Verify a *stopped, standalone* SQLite snapshot without changing it."""
    _require_standalone(path)
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("Backup file is missing or empty.")
    if expected_schema is not None and expected_schema < 1:
        raise ValueError("Expected schema must be a positive integer.")

    expected_hash = _expected_digest(expected_sha256)
    before = path.stat()
    digest = _file_sha256(path)
    if expected_hash is not None and not hmac.compare_digest(digest, expected_hash):
        raise ValueError("Backup SHA-256 does not match the expected value.")

    # as_uri() percent-encodes filenames containing '?' and '#', unlike raw file: paths.
    uri = f"{path.resolve().as_uri()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        # Never trust executable schema constructs in an externally supplied backup.
        # Keep this before integrity checks or any schema-derived reads.
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA query_only = ON")
        result = connection.execute("PRAGMA integrity_check").fetchone()
        integrity = str(result[0]) if result else ""
        if integrity.lower() != "ok":
            raise ValueError(f"SQLite integrity check failed: {integrity}")

        schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if schema < 1:
            raise ValueError("Backup has no NetWatch schema version.")
        if expected_schema is not None and schema != expected_schema:
            raise ValueError(f"Expected schema {expected_schema}, found {schema}.")

        present = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        missing = sorted(set(TABLES) - present)
        if missing:
            raise ValueError(f"Missing required NetWatch tables: {', '.join(missing)}.")

        for table, required in REQUIRED_COLUMNS.items():
            columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            absent = sorted(set(required) - columns)
            if absent:
                raise ValueError(f"Missing required columns in {table}: {', '.join(absent)}.")

        # Fetch one violation only; a damaged backup must not force an unbounded result.
        violation = connection.execute("PRAGMA foreign_key_check").fetchone()
        if violation is not None:
            raise ValueError("Backup contains foreign key violations.")

        counts = {
            table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in TABLES
        }

    _require_standalone(path)
    after = path.stat()
    if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        raise ValueError(
            "Backup file identity changed during verification; use an offline snapshot."
        )
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("Backup changed during verification; use an offline snapshot.")
    if not hmac.compare_digest(digest, _file_sha256(path)):
        raise ValueError("Backup content changed during verification; use an offline snapshot.")
    # Hashing is another filesystem operation: reject sidecars introduced during it.
    _require_standalone(path)

    return {
        "path": str(path.resolve()),
        "bytes": after.st_size,
        "sha256": digest,
        "integrity": integrity,
        "foreign_key_violations": 0,
        "schema_version": schema,
        "counts": counts,
        "read_only": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path)
    parser.add_argument("--expected-schema", type=int, default=None)
    parser.add_argument(
        "--expected-sha256",
        help="SHA-256 received through a separately trusted channel.",
        default=None,
    )
    args = parser.parse_args()
    try:
        report = verify(args.backup, args.expected_schema, args.expected_sha256)
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2
    print(json.dumps({"ok": True, **report}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
