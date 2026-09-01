from __future__ import annotations

import pytest

from flow_observability import (
    FlowObservabilityError,
    build_flow_observability_records,
)


def _flow(
    *,
    flow_id: str = "flow-1",
    source: str = "10.0.0.10",
    destination: str = "10.0.0.20",
) -> dict[str, object]:
    return {
        "flow_id": flow_id,
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
            },
        }
    ]
    assert "payload" not in repr(records).lower()
    assert "authorization" not in repr(records).lower()


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
