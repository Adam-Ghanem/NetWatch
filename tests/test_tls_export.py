from __future__ import annotations

import csv
import io
import json

import pytest

from tls_export import export_tls_investigator


def _snapshot():
    return {
        "items": [
            {
                "scan_run_id": 12,
                "observed_at": "2026-11-01T10:00:00+00:00",
                "ip_address": "2001:db8::10",
                "port": 443,
                "protocol": "TCP",
                "change_type": "tls_protocol_downgrade",
                "severity": "high",
                "summary": "Negotiated TLS protocol regressed.",
                "previous": "TLSv1.3",
                "current": "TLSv1.2",
                "alert_recommended": True,
                "alert_severity": "high",
                "alert_reason": "Evidence-backed downgrade",
                "secret": "should-never-be-exported",
                "certificate_body": "sensitive material",
            },
            {
                "scan_run_id": 13,
                "ip_address": "=2+2",
                "summary": "  @calc",
                "previous": "+cmd",
                "current": "-bad",
                "alert_recommended": False,
            },
        ]
    }


def test_json_export_is_versioned_bounded_and_allowlisted():
    data = json.loads(export_tls_investigator(_snapshot(), export_format="json", limit=1))
    assert data["schema_version"] == "netwatch.tls-change.v1"
    assert data["evidence_source"] == "retained_tls_service_metadata"
    assert data["count"] == 1
    assert data["events"][0]["ip_address"] == "2001:db8::10"
    assert data["events"][0]["alert_recommended"] is True
    assert data["privacy"]["ip_addresses_included"] is True
    assert data["privacy"]["network_probes_added"] is False
    assert "secret" not in str(data)
    assert "certificate_body" not in str(data)


def test_csv_export_neutralizes_formula_injection_and_keeps_fixed_columns():
    raw = export_tls_investigator(_snapshot(), export_format="csv", limit=2)
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8"))))
    assert len(rows) == 2
    assert rows[1]["ip_address"] == "'=2+2"
    assert rows[1]["summary"] == "'@calc"
    assert rows[1]["previous"] == "'+cmd"
    assert rows[1]["current"] == "'-bad"
    assert "secret" not in rows[0]
    assert "certificate_body" not in rows[0]


def test_ndjson_is_one_event_per_line_with_no_empty_placeholder():
    raw = export_tls_investigator(_snapshot(), export_format="ndjson", limit=2)
    events = [json.loads(line) for line in raw.splitlines()]
    assert len(events) == 2
    assert all(event["schema_version"] == "netwatch.tls-change.v1" for event in events)
    assert export_tls_investigator({"items": []}, export_format="ndjson") == b""


def test_empty_csv_preserves_columns():
    raw = export_tls_investigator({"items": []}, export_format="csv")
    assert "schema_version,evidence_source" in raw.decode("utf-8")


@pytest.mark.parametrize("limit", [0, -1, 1001])
def test_export_rejects_invalid_limits(limit):
    with pytest.raises(ValueError, match="limit"):
        export_tls_investigator(_snapshot(), export_format="json", limit=limit)


def test_export_rejects_unsupported_format_and_malformed_snapshot():
    with pytest.raises(ValueError, match="format"):
        export_tls_investigator(_snapshot(), export_format="xml")
    with pytest.raises(ValueError, match="list"):
        export_tls_investigator({"items": "not a list"}, export_format="json")
