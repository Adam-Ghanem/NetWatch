from __future__ import annotations

import csv
import io
import json

import pytest

import netwatch_udp


def _rows() -> list[dict[str, object]]:
    return [
        {
            "Port": 53,
            "Protocol": "UDP",
            "Service": "DNS",
            "Status": "Open",
            "Response Time (ms)": 1.2,
            "Service Detection": "DNS response",
            "Service Product": "DNS",
            "Service Version": "",
            "Service Confidence": "High",
        }
    ]


def test_requires_explicit_authorization() -> None:
    with pytest.raises(SystemExit) as exc:
        netwatch_udp.main(["192.168.1.10"])
    assert exc.value.code == 2


def test_default_profiles_are_bounded_and_json_serialized(monkeypatch, capsys) -> None:
    observed: dict[str, object] = {}

    def fake_scan(target, *, services, timeout):
        observed.update(target=target, services=services, timeout=timeout)
        return _rows()

    monkeypatch.setattr(netwatch_udp, "scan_udp_services", fake_scan)

    assert netwatch_udp.main(["192.168.1.10", "--authorized"]) == 0

    assert observed == {
        "target": "192.168.1.10",
        "services": ("dns", "ntp"),
        "timeout": 0.35,
    }
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1
    assert payload["items"][0]["Status"] == "Open"


def test_selected_profile_and_timeout_are_forwarded(monkeypatch, capsys) -> None:
    observed: dict[str, object] = {}

    def fake_scan(target, *, services, timeout):
        observed.update(target=target, services=services, timeout=timeout)
        return _rows()

    monkeypatch.setattr(netwatch_udp, "scan_udp_services", fake_scan)

    assert (
        netwatch_udp.main(
            [
                "fd00::10",
                "--authorized",
                "--service",
                "dns",
                "--timeout",
                "0.5",
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert observed == {"target": "fd00::10", "services": ("dns",), "timeout": 0.5}


def test_csv_output_is_machine_readable(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        netwatch_udp, "scan_udp_services", lambda *args, **kwargs: _rows()
    )

    assert (
        netwatch_udp.main(
            ["192.168.1.10", "--authorized", "--service", "dns", "--format", "csv"]
        )
        == 0
    )

    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert rows == [
        {
            "Port": "53",
            "Protocol": "UDP",
            "Service": "DNS",
            "Status": "Open",
            "Response Time (ms)": "1.2",
            "Service Detection": "DNS response",
            "Service Product": "DNS",
            "Service Version": "",
            "Service Confidence": "High",
        }
    ]


def test_scanner_validation_error_becomes_cli_usage_error(monkeypatch) -> None:
    def fake_scan(*args, **kwargs):
        raise ValueError("UDP timeout must be between 0.05 and 1.0 seconds.")

    monkeypatch.setattr(netwatch_udp, "scan_udp_services", fake_scan)

    with pytest.raises(SystemExit) as exc:
        netwatch_udp.main(["192.168.1.10", "--authorized", "--timeout", "2"])
    assert exc.value.code == 2
