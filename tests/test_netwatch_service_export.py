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


def test_cli_supports_ndjson_without_extra_blank_lines(monkeypatch, capsys) -> None:
    line = '{"schema_version":"netwatch.service.v1","ip_address":"192.0.2.10"}\n'
    monkeypatch.setattr(
        netwatch_service_export,
        "export_recent_service_evidence",
        lambda **_: line,
    )

    assert netwatch_service_export.main(["--format", "ndjson"]) == 0
    assert capsys.readouterr().out == line


def test_cli_describes_contract_without_querying_persisted_data(monkeypatch, capsys) -> None:
    def unexpected_query(**_kwargs) -> str:
        raise AssertionError("contract discovery must not query persisted evidence")

    monkeypatch.setattr(
        netwatch_service_export,
        "export_recent_service_evidence",
        unexpected_query,
    )

    assert netwatch_service_export.main(["--describe-contract"]) == 0
    manifest = json.loads(capsys.readouterr().out)

    assert manifest["schema_version"] == "netwatch.service.v1"
    assert manifest["formats"] == ["json", "ndjson", "csv"]
    assert manifest["max_records"] == 1000
    assert manifest["schema_path"] == "schemas/netwatch-service-v1.schema.json"
    assert manifest["compatibility"] == {
        "major_version": 1,
        "unknown_fields": "reject",
        "field_order_stable_for_csv": True,
    }
    assert manifest["privacy"] == {
        "payload_retained": False,
        "packet_payload_fields": False,
        "credential_fields": False,
    }
    assert "ip_address" in manifest["fields"]
    assert "payload_retained" in manifest["fields"]


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
