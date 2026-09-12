import csv
import io
import json

import netwatch_udp


def _rows(status: str) -> list[dict[str, object]]:
    return [{"Port": 53, "Protocol": "UDP", "Service": "DNS", "Status": status}]


def test_normalized_rows_preserve_open_filtered_semantics():
    row = netwatch_udp._normalized_rows(
        "192.168.1.10",
        _rows("Open|Filtered"),
        observed_at="2026-09-11T17:49:06.000Z",
    )[0]
    assert row["Evidence Schema"] == "netwatch.udp-service-evidence"
    assert row["Schema Version"] == 1
    assert row["Observed At"] == "2026-09-11T17:49:06.000Z"
    assert row["Address Family"] == "IPv4"
    assert row["Evidence Source"] == "active_udp_probe"
    assert row["Evidence Semantics"] == "no_response"
    assert row["Status"] == "Open|Filtered"


def test_normalized_rows_mark_ipv6_and_explicit_refusal():
    row = netwatch_udp._normalized_rows("fd00::10", _rows("Closed"))[0]
    assert row["Address Family"] == "IPv6"
    assert row["Evidence Semantics"] == "explicit_refusal"
    assert str(row["Observed At"]).endswith("Z")


def test_json_envelope_is_self_describing(monkeypatch, capsys):
    monkeypatch.setattr(netwatch_udp, "scan_udp_services", lambda *_args, **_kwargs: _rows("Open"))
    assert netwatch_udp.main(["192.168.1.10", "--authorized"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == "netwatch.udp-service-evidence"
    assert payload["schema_version"] == 1
    assert payload["observed_at"].endswith("Z")
    assert payload["address_family"] == "IPv4"
    assert payload["items"][0]["Observed At"] == payload["observed_at"]
    assert payload["items"][0]["Evidence Semantics"] == "response_observed"


def test_csv_export_carries_schema_semantics_and_timestamp(monkeypatch, capsys):
    monkeypatch.setattr(
        netwatch_udp,
        "scan_udp_services",
        lambda *_args, **_kwargs: _rows("Open|Filtered"),
    )
    assert netwatch_udp.main(["fd00::10", "--authorized", "--format", "csv"]) == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert rows[0]["Evidence Schema"] == "netwatch.udp-service-evidence"
    assert rows[0]["Schema Version"] == "1"
    assert rows[0]["Observed At"].endswith("Z")
    assert rows[0]["Address Family"] == "IPv6"
    assert rows[0]["Evidence Semantics"] == "no_response"


def test_invalid_target_family_is_unknown_without_reinterpreting_status():
    row = netwatch_udp._normalized_rows("not-an-ip", _rows("Blocked"))[0]
    assert row["Address Family"] == "Unknown"
    assert row["Evidence Semantics"] == "validation_blocked"


def test_normalized_rows_keep_export_provenance_authoritative():
    row = netwatch_udp._normalized_rows(
        "192.168.1.10",
        [
            {
                "Port": 53,
                "Protocol": "UDP",
                "Service": "DNS",
                "Status": "Open",
                "Run ID": "spoofed",
                "Observed At": "1900-01-01T00:00:00Z",
                "Target": "203.0.113.99",
                "Destination Address": "203.0.113.99",
                "Address Family": "IPv6",
                "Network Transport": "tcp",
                "Network Protocol": "http",
                "Evidence Source": "untrusted",
                "Event Type": "other",
                "Evidence Semantics": "unknown",
            }
        ],
        observed_at="2026-09-12T15:00:00.000Z",
        run_id="run-123",
    )[0]

    assert row["Run ID"] == "run-123"
    assert row["Observed At"] == "2026-09-12T15:00:00.000Z"
    assert row["Target"] == "192.168.1.10"
    assert row["Destination Address"] == "192.168.1.10"
    assert row["Address Family"] == "IPv4"
    assert row["Network Transport"] == "udp"
    assert row["Network Protocol"] == "dns"
    assert row["Evidence Source"] == "active_udp_probe"
    assert row["Event Type"] == "udp_service_evidence"
    assert row["Evidence Semantics"] == "response_observed"
