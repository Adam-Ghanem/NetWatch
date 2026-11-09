"""CLI contract regression checks for the offline backup verifier."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from scripts import verify_sqlite_backup


@pytest.mark.parametrize(
    ("expected", "failure", "exit_code"),
    [
        ("a" * 64, False, 0),
        ("b" * 64, True, 2),
    ],
)
def test_backup_cli_emits_machine_readable_status(
    monkeypatch, capsys, tmp_path, expected, failure, exit_code
):
    """Automation must never mistake a rejected digest for a valid backup."""
    snapshot = tmp_path / "snapshot.sqlite3"
    snapshot.write_bytes(b"offline-test-placeholder")
    calls = []

    def fake_verify(path: Path, expected_schema=None, expected_sha256=None):
        calls.append((path, expected_schema, expected_sha256))
        if failure:
            raise ValueError("Backup SHA-256 does not match the expected value.")
        return {"sha256": expected, "read_only": True}

    monkeypatch.setattr(verify_sqlite_backup, "verify", fake_verify)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "verify_sqlite_backup.py",
            "--expected-schema",
            "11",
            "--expected-sha256",
            expected,
            str(snapshot),
        ],
    )

    assert verify_sqlite_backup.main() == exit_code
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is (not failure)
    assert calls == [(snapshot, 11, expected)]
    if failure:
        assert "SHA-256" in payload["error"]
    else:
        assert payload["sha256"] == expected
        assert payload["read_only"] is True
