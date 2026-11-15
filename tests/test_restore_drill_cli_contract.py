"""CLI contract checks for the offline restore timing evidence helper."""

from __future__ import annotations

import json
import sys

import pytest

from scripts.measure_restore_drill import main


def test_cli_emits_machine_readable_observations(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "measure_restore_drill.py",
            "--last-durable",
            "2026-11-15T09:00:00Z",
            "--failure",
            "2026-11-15T09:03:00Z",
            "--ready",
            "2026-11-15T09:05:30Z",
        ],
    )
    assert main() == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["observed_rpo_seconds"] == 180.0
    assert report["observed_rto_seconds"] == 150.0
    assert "not production SLA" in report["scope"]


@pytest.mark.parametrize(
    "last_durable,failure,ready",
    [
        ("2026-11-15T09:04:00Z", "2026-11-15T09:03:00Z", "2026-11-15T09:05:00Z"),
        ("2026-11-15T09:00:00Z", "2026-11-15T09:03:00Z", "2026-11-15T09:02:00Z"),
        ("2026-11-15T09:00:00", "2026-11-15T09:03:00Z", "2026-11-15T09:05:00Z"),
        ("2026-11-15T09:00:00-00:00", "2026-11-15T09:03:00Z", "2026-11-15T09:05:00Z"),
    ],
)
def test_cli_rejects_invalid_evidence_without_json(
    monkeypatch, capsys, last_durable, failure, ready
):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "measure_restore_drill.py",
            "--last-durable",
            last_durable,
            "--failure",
            failure,
            "--ready",
            ready,
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error:" in captured.err


@pytest.mark.parametrize(
    "last_durable",
    ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"],
)
def test_cli_reports_utc_overflow_without_traceback(monkeypatch, capsys, last_durable):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "measure_restore_drill.py",
            "--last-durable",
            last_durable,
            "--failure",
            "2026-11-15T09:03:00Z",
            "--ready",
            "2026-11-15T09:05:00Z",
        ],
    )
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "supported UTC range" in captured.err
    assert "Traceback" not in captured.err
