import json

import pytest

import netwatch_service_export


def test_cli_forwards_bounded_filters_and_writes_json(monkeypatch, capsys) -> None:
    calls: list[dict[str, object]] = []

    def export_recent_service_evidence(**kwargs) -> str:
        calls.append(kwargs)
        return json.dumps({"schema_version": "netwatch.service.v1", "count": 0, "items": []})

    monkeypatch.setattr(
        netwatch_service_export,
        "export_recent_service_evidence",
        export_recent_service_evidence,
    )

    result = netwatch_service_export.main(
        [
            "--format",
            "json",
            "--limit",
            "25",
            "--scan-run-id",
            "17",
            "--ip-address",
            "2001:db8::10",
        ]
    )

    assert result == 0
    assert calls == [
        {
            "output_format": "json",
            "limit": 25,
            "scan_run_id": 17,
            "ip_address": "2001:db8::10",
        }
    ]
    assert json.loads(capsys.readouterr().out)["schema_version"] == "netwatch.service.v1"


def test_cli_supports_csv_without_modifying_payload(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        netwatch_service_export,
        "export_recent_service_evidence",
        lambda **_: "schema_version,ip_address\r\nnetwatch.service.v1,192.0.2.10\r\n",
    )

    assert netwatch_service_export.main(["--format", "csv"]) == 0
    assert capsys.readouterr().out == (
        "schema_version,ip_address\r\nnetwatch.service.v1,192.0.2.10\r\n"
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["--limit", "0"],
        ["--limit", "1001"],
        ["--scan-run-id", "0"],
        ["--format", "xml"],
    ],
)
def test_cli_rejects_unbounded_or_unsupported_arguments(argv) -> None:
    with pytest.raises(SystemExit) as exc_info:
        netwatch_service_export.main(argv)

    assert exc_info.value.code == 2
