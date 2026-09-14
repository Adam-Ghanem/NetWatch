import json

from flow_export import (
    FLOW_EXPORT_EVIDENCE_SOURCE,
    FLOW_EXPORT_SCHEMA_VERSION,
    export_flows_json,
    export_flows_ndjson,
)
from flow_schema import FLOW_SCHEMA_VERSION, load_flow_schema


def _flow() -> dict[str, object]:
    return {
        "flow_id": "flow-schema-test",
        "community_id": "1:example",
        "protocol": "TCP",
        "service": "https",
        "tcp_state": "established",
        "endpoint_a": {"ip": "192.0.2.10", "port": 51515},
        "endpoint_b": {"ip": "192.0.2.20", "port": 443},
        "originator": {"ip": "192.0.2.10", "port": 51515},
        "responder": {"ip": "192.0.2.20", "port": 443},
        "packets": 5,
        "bytes": 640,
        "a_to_b_packets": 3,
        "a_to_b_bytes": 400,
        "b_to_a_packets": 2,
        "b_to_a_bytes": 240,
        "originator_packets": 3,
        "originator_bytes": 400,
        "responder_packets": 2,
        "responder_bytes": 240,
        "first_seen": "2026-09-14T12:00:00+00:00",
        "last_seen": "2026-09-14T12:00:00.250000+00:00",
        "duration_ms": 250,
    }


def test_json_schema_identity_and_privacy_contract_match_export_constants():
    schema = load_flow_schema("json")
    properties = schema["properties"]

    assert FLOW_SCHEMA_VERSION == FLOW_EXPORT_SCHEMA_VERSION
    assert properties["schema_version"]["const"] == FLOW_EXPORT_SCHEMA_VERSION
    assert properties["evidence_source"]["const"] == FLOW_EXPORT_EVIDENCE_SOURCE
    assert properties["payload_retained"]["const"] is False
    assert properties["flows"]["maxItems"] == 1000
    assert schema["additionalProperties"] is False


def test_json_schema_required_fields_cover_emitted_envelope_and_flow_record():
    schema = load_flow_schema("json")
    payload = json.loads(export_flows_json([_flow()]).decode("utf-8"))
    flow = payload["flows"][0]

    assert set(schema["required"]).issubset(payload)
    assert set(schema["$defs"]["flow"]["required"]).issubset(flow)
    assert "payload" not in schema["$defs"]["flow"]["properties"]
    assert "raw" not in schema["$defs"]["flow"]["properties"]


def test_ndjson_schema_required_fields_cover_emitted_event():
    schema = load_flow_schema("ndjson")
    event = json.loads(export_flows_ndjson([_flow()]).decode("utf-8"))

    assert set(schema["required"]).issubset(event)
    assert schema["properties"]["event_type"]["const"] == "flow"
    assert schema["properties"]["schema_version"]["const"] == FLOW_EXPORT_SCHEMA_VERSION
    assert schema["properties"]["evidence_source"]["const"] == FLOW_EXPORT_EVIDENCE_SOURCE
    assert schema["properties"]["payload_retained"]["const"] is False
    assert "payload" not in schema["properties"]
    assert "raw" not in schema["properties"]
