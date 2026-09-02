import csv
import io
import json

import pytest

from flow_report_export import export_flows_csv, export_flows_json


def _flow() -> dict[str, object]:
    return {
        "flow_id": "abc123",
        "protocol": "TCP",
        "service": "https",
        "originator": {"ip": "192.168.1.10", "port": 51515},
        "responder": {"ip": "192.168.1.20", "port": 443},
        "packets": 7,
        "bytes": 2048,
        "originator_packets": 4,
        "originator_bytes": 1200,
        "responder_packets": 3,
        "responder_bytes": 848,
        "first_seen": "2026-09-02T00:00:00.000+00:00",
        "last_seen": "2026-09-02T00:00:02.500+00:00",
        "duration_ms": 2500,
        "tcp_state": "established",
        "payload": "SECRET",
        "authorization": "Bearer SECRET",
        "metadata": {"cookie": "SECRET"},
    }


def test_json_export_is_bounded_metadata_only_and_schema_versioned():
    payload = export_flows_json([_flow()], limit=100)
    document = json.loads(payload)

    assert document["schema"] == "netwatch.flow-report.v1"
    assert document["flow_count"] == 1
    assert document["payload_retained"] is False
    assert document["flows"][0]["flow_id"] == "abc123"
    serialized = json.dumps(document).lower()
    assert "secret" not in serialized
    assert "authorization" not in serialized
    assert "cookie" not in serialized
    assert "payload" not in document["flows"][0]


def test_csv_export_has_stable_flat_columns_without_sensitive_fields():
    payload = export_flows_csv([_flow()], limit=100)
    rows = list(csv.DictReader(io.StringIO(payload)))

    assert len(rows) == 1
    row = rows[0]
    assert row["flow_id"] == "abc123"
    assert row["originator_ip"] == "192.168.1.10"
    assert row["responder_port"] == "443"
    assert row["bytes"] == "2048"
    assert "payload" not in row
    assert "authorization" not in row
    assert "metadata" not in row
    assert "SECRET" not in payload


def test_export_limits_fail_closed():
    with pytest.raises(ValueError, match="between 1 and 1000"):
        export_flows_json([_flow()], limit=0)
    with pytest.raises(ValueError, match="between 1 and 1000"):
        export_flows_csv([_flow()], limit=1001)


def test_export_truncates_to_requested_limit():
    flows = [{**_flow(), "flow_id": str(index)} for index in range(3)]
    document = json.loads(export_flows_json(flows, limit=2))

    assert document["flow_count"] == 2
    assert [item["flow_id"] for item in document["flows"]] == ["0", "1"]
