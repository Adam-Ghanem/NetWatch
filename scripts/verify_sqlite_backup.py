#!/usr/bin/env python3
"""Strict, read-only verification of an offline NetWatch SQLite backup.

SQLite checks run against a private copy of the exact bytes hashed from one
open source descriptor. This checks structure and transport integrity, not
encryption, off-host rotation, audit HMAC keys, or a successful application
restore.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import tempfile
from collections.abc import Iterator
from contextlib import closing, contextmanager
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


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _ensure_source_unchanged(path: Path, source_fd: int, original: os.stat_result) -> None:
    try:
        descriptor_state = os.fstat(source_fd)
        path_state = path.lstat()
    except OSError as exc:
        raise ValueError("Backup changed during verification; use an offline snapshot.") from exc

    if stat.S_ISLNK(path_state.st_mode):
        raise ValueError("Backup became a symbolic link during verification.")
    if (
        not stat.S_ISREG(path_state.st_mode)
        or not _same_file_state(original, descriptor_state)
        or not _same_file_state(original, path_state)
    ):
        raise ValueError("Backup changed during verification; use an offline snapshot.")


@contextmanager
def _snapshot_backup(path: Path) -> Iterator[tuple[Path, str, int]]:
    """Copy a stable regular input into a private temporary snapshot and hash it."""
    try:
        path_state = path.lstat()
    except OSError as exc:
        raise ValueError("Backup file is missing or unavailable.") from exc

    if not stat.S_ISREG(path_state.st_mode) or path_state.st_size == 0:
        raise ValueError("Backup file is missing or empty, or not a regular file.")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        source_fd = os.open(path, flags)
    except OSError as exc:
        raise ValueError("Backup file cannot be opened safely.") from exc

    try:
        original = os.fstat(source_fd)
        if not stat.S_ISREG(original.st_mode) or not _same_file_state(path_state, original):
            raise ValueError("Backup changed before verification; use an offline snapshot.")

        # Keep the existing path hash checks as defense in depth and to detect
        # source changes around the descriptor-backed copy.
        initial_digest = _file_sha256(path)
        _ensure_source_unchanged(path, source_fd, original)

        with tempfile.TemporaryDirectory(prefix="netwatch-backup-verify-") as temporary_dir:
            snapshot_fd, snapshot_name = tempfile.mkstemp(
                prefix="snapshot-",
                suffix=".sqlite3",
                dir=temporary_dir,
            )
            digest = hashlib.sha256()
            copied = 0
            with os.fdopen(snapshot_fd, "wb") as snapshot:
                with os.fdopen(os.dup(source_fd), "rb") as source:
                    for chunk in iter(lambda: source.read(_HASH_CHUNK_BYTES), b""):
                        snapshot.write(chunk)
                        digest.update(chunk)
                        copied += len(chunk)
                snapshot.flush()
                os.fsync(snapshot.fileno())

            if copied != original.st_size:
                raise ValueError("Backup changed during verification; use an offline snapshot.")

            snapshot_digest = digest.hexdigest()
            if not hmac.compare_digest(initial_digest, snapshot_digest):
                raise ValueError("Backup content changed while snapshotting; use an offline snapshot.")
            _ensure_source_unchanged(path, source_fd, original)

            yield Path(snapshot_name), snapshot_digest, copied

            # SQLite inspected the private copy. Recheck the source descriptor and
            # path before accepting the result, then compare the final path digest.
            _ensure_source_unchanged(path, source_fd, original)
            final_digest = _file_sha256(path)
            if not hmac.compare_digest(snapshot_digest, final_digest):
                raise ValueError("Backup content changed during verification; use an offline snapshot.")
            _ensure_source_unchanged(path, source_fd, original)
    finally:
        os.close(source_fd)


def verify(
    path: Path,
    expected_schema: int | None = None,
    expected_sha256: str | None = None,
) -> dict[str, object]:
    """Verify a *stopped, standalone* SQLite snapshot without changing its source."""
    expected_hash = _expected_digest(expected_sha256)
    if expected_schema is not None and expected_schema < 1:
        raise ValueError("Expected schema must be a positive integer.")

    with _snapshot_backup(path) as (snapshot_path, digest, byte_count):
        if expected_hash is not None and not hmac.compare_digest(digest, expected_hash):
            raise ValueError("Backup SHA-256 does not match the expected value.")

        # The private snapshot is the exact byte sequence used for hashing and SQLite checks.
        uri = f"{snapshot_path.resolve().as_uri()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as connection:
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

            # Fetch one violation only; a damaged backup must not force an unbounded result.
            violation = connection.execute("PRAGMA foreign_key_check").fetchone()
            if violation is not None:
                raise ValueError("Backup contains foreign key violations.")

            counts = {
                table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in TABLES
            }

        return {
            "path": str(path.resolve()),
            "bytes": byte_count,
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
