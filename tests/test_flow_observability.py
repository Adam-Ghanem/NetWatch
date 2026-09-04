from __future__ import annotations

import pytest

from flow_observability import FlowObservabilityError, build_flow_observability_records


def _flow(
    *,
    flow_id: str = "flow-1",
    source: str = "10.0.0.10",
    destination: str = "10.0.0.20",
) -> dict[str, object]:
    return {
        "flow_id": flow_id,
        "community_id": "1:7YVf8u8bz4qS6fUiR7mUp4lO3/8=",
        "originator": {"ip": source, "port": 51_234},
        "responder": {"ip": destination, "port": 443},
        "protocol": "TCP",
        "service": "https",
        "state": "established",
        "packets": 8,
        "bytes": 1_200,
        "originator_packets": 3,
        "originator_bytes": 200,
        "responder_packets": 5,
        "responder_bytes": 1_000,
        "duration_ms": 250,
        "protocol_event_count": 3,
        "protocol_events": [
            {
                "event_type": "tls",
                "metadata": {
                    "server_name": "private.example",
                    "alpn": "h2",
                },
            },
            {
                "event_type": "http",
                "metadata": {
                    "host": "private.example",
                    "method": "GET",
                    "path": "/secret",
                },
            },
            {"event_type": "tls", "metadata": {"server_name": "duplicate.example"}},
        ],
        "payload": "must-not-export",
        "metadata": {"authorization": "must-not-export"},
    }


def test_build_flow_observability_records_maps_safe_semantic_attributes():
    records = build_flow_observability_records([_flow()])

    assert records == [
        {
            "schema": "netwatch.flow.v1",
            "attributes": {
                "netwatch.flow.id": "flow-1",
                "network.community_id": "1:7YVf8u8bz4qS6fUiR7mUp4lO3/8=",
                "source.address": "10.0.0.10",
                "source.port": 51_234,
                "destination.address": "10.0.0.20",
                "destination.port": 443,
                "network.transport": "tcp",
                "network.type": "ipv4",
                "network.protocol.name": "https",
                "netwatch.flow.state": "established",
                "netwatch.flow.packets": 8,
                "netwatch.flow.bytes": 1_200,
                "netwatch.flow.originator.packets": 3,
                "netwatch.flow.originator.bytes": 200,
                "netwatch.flow.responder.packets": 5,
                "netwatch.flow.responder.bytes": 1_000,
                "netwatch.flow.duration_ms": 250,
                "netwatch.flow.protocol_event_count": 3,
                "netwatch.flow.protocol_event_types": ["tls", "http"],
            },
        }
    ]
    serialized = repr(records).lower()
    for forbidden in (
        "payload",
        "authorization",
        "private.example",
        "duplicate.example",
        "/secret",
        "server_name",
    ):
        assert forbidden not in serialized


def test_flow_observability_protocol_signals_are_allowlisted_and_bounded():
    flow = _flow()
    flow["protocol_event_count"] = 50_000
    flow["protocol_events"] = [
        {"event_type": "dns", "metadata": {"query": "secret.example"}},
        {"event_type": "unknown", "metadata": {"value": "must-not-export"}},
        {"event_type": "http", "metadata": {"host": "secret.example"}},
        {"event_type": "tls", "metadata": {"server_name": "secret.example"}},
    ]

    attributes = build_flow_observability_records([flow])[0]["attributes"]

    assert attributes["netwatch.flow.protocol_event_count"] == 1_000
    assert attributes["netwatch.flow.protocol_event_types"] == ["dns", "http", "tls"]
    assert "secret.example" not in repr(attributes)
    assert "must-not-export" not in repr(attributes)


def test_flow_observability_is_ipv6_aware_and_bounded():
    flows = [
        _flow(
            flow_id=f"flow-{index}",
            source="2001:db8::10",
            destination="2001:db8::20",
        )
        for index in range(3)
    ]

    records = build_flow_observability_records(flows, limit=2)

    assert len(records) == 2
    assert all(record["attributes"]["network.type"] == "ipv6" for record in records)

    with pytest.raises(FlowObservabilityError, match="limit"):
        build_flow_observability_records(flows, limit=0)
    with pytest.raises(FlowObservabilityError, match="limit"):
        build_flow_observability_records(flows, limit=1_001)
