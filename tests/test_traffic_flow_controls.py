from __future__ import annotations

import pytest

from flow_display_filter import FlowDisplayFilterError
from traffic_flow_controls import TrafficFlowControls, apply_traffic_flow_controls

CAPTURE_RESULT = {
    "interface": "eth0",
    "captured_packets": 12,
    "captured_bytes": 2400,
    "payload_retained": False,
    "flow_count": 3,
    "flows": [
        {
            "flow_id": "flow-https",
            "protocol": "TCP",
            "service": "https",
            "tcp_state": "established",
            "originator": {"ip": "10.0.0.10", "port": 51000},
            "responder": {"ip": "10.0.0.20", "port": 443},
            "packets": 8,
            "bytes": 1600,
            "originator_packets": 5,
            "originator_bytes": 1000,
            "responder_packets": 3,
            "responder_bytes": 600,
            "duration_ms": 250,
            "payload": "must-never-leak",
        },
        {
            "flow_id": "flow-dns",
            "protocol": "UDP",
            "service": "dns",
            "originator": {"ip": "10.0.0.10", "port": 53000},
            "responder": {"ip": "10.0.0.53", "port": 53},
            "packets": 2,
            "bytes": 300,
            "originator_packets": 1,
            "originator_bytes": 100,
            "responder_packets": 1,
            "responder_bytes": 200,
            "duration_ms": 20,
        },
        {
            "flow_id": "flow-ssh",
            "protocol": "TCP",
            "service": "ssh",
            "tcp_state": "reset",
            "originator": {"ip": "10.0.0.30", "port": 52000},
            "responder": {"ip": "10.0.0.40", "port": 22},
            "packets": 2,
            "bytes": 500,
            "originator_packets": 2,
            "originator_bytes": 500,
            "responder_packets": 0,
            "responder_bytes": 0,
            "duration_ms": 10,
        },
    ],
    "conversations": [{"legacy": True}],
}


def test_default_controls_preserve_capture_response_compatibility():
    result = apply_traffic_flow_controls(CAPTURE_RESULT, TrafficFlowControls())

    assert result == CAPTURE_RESULT
    assert result is not CAPTURE_RESULT


def test_controls_compose_filter_query_sort_scrubbing_and_conversation_pivots():
    controls = TrafficFlowControls(
        display_filter="protocol == tcp and bytes >= 400",
        ip_address="10.0.0.10",
        min_bytes=1000,
        sort_by="bytes",
        limit=1,
    )

    result = apply_traffic_flow_controls(CAPTURE_RESULT, controls)
    flows = result["flows"]

    assert result["flow_count"] == 1
    assert isinstance(flows, list)
    assert len(flows) == 1
    assert isinstance(flows[0], dict)
    assert flows[0]["flow_id"] == "flow-https"
    assert "payload" not in flows[0]
    assert result["conversation_count"] == 1
    assert result["endpoint_count"] == 2
    assert result["conversation_totals"] == {"packets": 8, "bytes": 1600}
    assert result["conversations"] == [
        {
            "flow_id": "flow-https",
            "protocol": "TCP",
            "service": "https",
            "source": {"ip": "10.0.0.10", "port": 51000},
            "destination": {"ip": "10.0.0.20", "port": 443},
            "packets": 8,
            "bytes": 1600,
            "source_to_destination_packets": 5,
            "source_to_destination_bytes": 1000,
            "destination_to_source_packets": 3,
            "destination_to_source_bytes": 600,
            "first_seen": None,
            "last_seen": None,
            "duration_ms": 250,
            "tcp_state": "established",
        }
    ]
    assert result["endpoints"] == [
        {
            "ip": "10.0.0.10",
            "packets": 8,
            "bytes": 1600,
            "sent_packets": 5,
            "sent_bytes": 1000,
            "received_packets": 3,
            "received_bytes": 600,
            "conversation_count": 1,
        },
        {
            "ip": "10.0.0.20",
            "packets": 8,
            "bytes": 1600,
            "sent_packets": 3,
            "sent_bytes": 600,
            "received_packets": 5,
            "received_bytes": 1000,
            "conversation_count": 1,
        },
    ]
    assert result["flow_analysis"] == {
        "applied": True,
        "input_flow_count": 3,
        "matched_flow_count": 1,
        "display_filter": "protocol == tcp and bytes >= 400",
        "sort_by": "bytes",
        "limit": 1,
        "conversation_pivots_recomputed": True,
    }


def test_controls_recompute_empty_conversation_pivots_without_stale_rows():
    result = apply_traffic_flow_controls(
        CAPTURE_RESULT,
        TrafficFlowControls(service="does-not-exist"),
    )

    assert result["flows"] == []
    assert result["flow_count"] == 0
    assert result["conversations"] == []
    assert result["conversation_count"] == 0
    assert result["endpoints"] == []
    assert result["endpoint_count"] == 0
    assert result["conversation_totals"] == {"packets": 0, "bytes": 0}


def test_invalid_display_filter_fails_closed():
    with pytest.raises(FlowDisplayFilterError, match="Unsupported field"):
        apply_traffic_flow_controls(
            CAPTURE_RESULT,
            TrafficFlowControls(display_filter="payload == secret"),
        )


def test_invalid_query_limit_is_rejected():
    with pytest.raises(ValueError, match="between 1 and 1000"):
        apply_traffic_flow_controls(
            CAPTURE_RESULT,
            TrafficFlowControls(limit=1001),
        )
