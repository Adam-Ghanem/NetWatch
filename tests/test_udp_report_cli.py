from __future__ import annotations

import json

import pytest

import netwatch_udp_report


def test_auto_detects_json_envelope() -> None:
    rows = [{"Status": "Closed", "Evidence Verdict": "port_closed"}]
    assert netwatch_udp_report._load_rows(json.dumps({"items": rows}), "auto") == rows


def test_auto_detects_jsonl() -> None:
    rows = [{"Status": "Closed"}, {"Status": "Blocked"}]
    text = "\n".join(json.dumps(row) for row in rows) + "\n"
    assert netwatch_udp_report._load_rows(text, "auto") == rows


def test_csv_reader_preserves_exported_fields() -> None:
    text = "Status,Evidence Verdict\nClosed,port_closed\n"
    rows = netwatch_udp_report._load_rows(text, "csv")
    assert rows == [{"Status": "Closed", "Evidence Verdict": "port_closed"}]


def test_summary_envelope_does_not_return_source_records() -> None:
    rows = [
        {
            "Status": "Closed",
            "Evidence Verdict": "port_closed",
            "Evidence Semantics": "explicit_refusal",
            "Port State Verified": True,
            "Service Identity Verified": False,
            "UDP Response Bytes": 0,
        }
    ]
    payload = netwatch_udp_report._summary_envelope(rows)
    assert payload["schema"] == "netwatch.udp-service-evidence-summary"
    assert payload["count"] == 1
    assert payload["summary"]["verified_port_states"] == 1
    assert "items" not in payload


def test_json_envelope_requires_items() -> None:
    with pytest.raises(ValueError, match="must contain an 'items' list"):
        netwatch_udp_report._load_rows(json.dumps({"summary": {}}), "json")


def test_record_limit_is_enforced() -> None:
    rows = [{} for _ in range(netwatch_udp_report._MAX_RECORDS + 1)]
    with pytest.raises(ValueError, match="10,000-record"):
        netwatch_udp_report._validate_rows(rows)
