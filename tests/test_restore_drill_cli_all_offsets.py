"""Ensure CLI rejects unknown timezone evidence in every operator field."""

from __future__ import annotations

import json
import sys

import pytest

from scripts.measure_restore_drill import main


@pytest.mark.parametrize("field", ["--last-durable", "--failure", "--ready"])
def test_cli_unknown_offset_is_fail_closed_for_each_field(monkeypatch, capsys, field):
    args = {
        "--last-durable": "2026-11-15T09:00:00+00:00",
        "--failure": "2026-11-15T09:03:00+00:00",
        "--ready": "2026-11-15T09:05:00+00:00",
    }
    args[field] = args[field].replace("+00:00", "-00:00")
    monkeypatch.setattr(
        sys,
        "argv",
        ["measure_restore_drill.py"]
        + [value for key, timestamp in args.items() for value in (key, timestamp)],
    )

    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "timezone offset must be known" in captured.err
    assert "Traceback" not in captured.err


def test_cli_known_zero_offset_preserves_observations(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "measure_restore_drill.py",
            "--last-durable",
            "2026-11-15T09:00:00+00:00",
            "--failure",
            "2026-11-15T09:03:00+00:00",
            "--ready",
            "2026-11-15T09:05:00+00:00",
        ],
    )
    assert main() == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    report = json.loads(captured.out)
    assert report["observed_rpo_seconds"] == 180.0
    assert report["observed_rto_seconds"] == 120.0
