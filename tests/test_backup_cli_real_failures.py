"""Real verifier CLI rejection tests, without mocked verification logic."""

from __future__ import annotations

import json
import sys

import pytest

from scripts import verify_sqlite_backup


@pytest.mark.parametrize(
    ("scenario", "expected_error"),
    [
        ("missing", "missing or empty"),
        ("empty", "missing or empty"),
        ("invalid_digest", "64 hexadecimal characters"),
    ],
)
def test_backup_cli_real_failures_are_json_and_nonzero(
    monkeypatch, capsys, tmp_path, scenario, expected_error
):
    """An offline automation must fail closed for invalid backup inputs."""
    snapshot = tmp_path / "snapshot.sqlite3"
    arguments = ["verify_sqlite_backup.py", str(snapshot)]

    if scenario == "empty":
        snapshot.touch()
    elif scenario == "invalid_digest":
        snapshot.write_bytes(b"not-a-database")
        arguments = [
            "verify_sqlite_backup.py",
            "--expected-sha256",
            "not-a-sha256",
            str(snapshot),
        ]

    monkeypatch.setattr(sys, "argv", arguments)

    assert verify_sqlite_backup.main() == 2
    result = json.loads(capsys.readouterr().out)
    assert result["ok"] is False
    assert expected_error in result["error"]
    assert "sha256" not in result
