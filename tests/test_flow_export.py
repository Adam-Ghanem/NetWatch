import json

import pytest

from flow_export import export_flows_csv, export_flows_json


def _flow(flow_id: str = "flow-1", *, service: str = "https") -> dict[str, object]:
    return {
        "flow_id": flow_id,
        "protocol": "TCP",
        "service": service,
        "tcp_state": "established",
        "originator": {"ip": "192.168.1.10", "port": 51_515},
        "responder": {"ip": "192.168.1.20", "port": 443},
        "packets": 5,
        "bytes": 640,
        "originator_packets": 3,
        "originator_bytes": 400,
        "responder_packets": 2,
        "responder_bytes": 240,
        "first_seen": "2026-08-31T18:00:00.000+00:00",
        "last_seen": "2026-08-31T18:00:00.250+00:00",
        "duration_ms": 250,
        "payload": "must-never-export",
        "raw": "must-never-export",
    }


def test_json_export_is_bounded_and_allowlists_metadata_fields():
    payload = json.loads(export_flows_json([_flow()]).decode("utf-8"))

    assert payload["count"] == 1
    assert payload["payload_retained"] is False
    exported = payload["flows"][0]
    assert exported["flow_id"] == "flow-1"
    assert exported["originator"] == {"ip": "192.168.1.10", "port": 51_515}
    assert exported["responder"] == {"ip": "192.168.1.20", "port": 443}
    assert exported["originator_bytes"] == 400
    assert exported["responder_bytes"] == 240
    assert "payload" not in exported
    assert "raw" not in exported


def test_csv_export_flattens_endpoints_and_is_formula_safe():
    content = export_flows_csv([_flow(service="=UNTRUSTED()")]).decode("utf-8")

    header = content.splitlines()[0]
    assert "originator_ip" in header
    assert "responder_port" in header
    assert "payload" not in header
    assert "raw" not in header
    assert "192.168.1.10" in content
    assert "'=UNTRUSTED()" in content


def test_flow_exports_validate_limits_and_truncate_deterministically():
    flows = [_flow(f"flow-{index}") for index in range(3)]

    payload = json.loads(export_flows_json(flows, limit=2).decode("utf-8"))
    assert payload["count"] == 2
    assert [flow["flow_id"] for flow in payload["flows"]] == ["flow-0", "flow-1"]

    with pytest.raises(ValueError, match="between 1 and 1000"):
        export_flows_json(flows, limit=0)
    with pytest.raises(ValueError, match="between 1 and 1000"):
        export_flows_csv(flows, limit=1_001)
