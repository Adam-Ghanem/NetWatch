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
            "duration_ms": 10,
        },
    ],
    "conversations": [{"legacy": True}],
}


def test_default_controls_preserve_capture_response_compatibility():
    result = apply_traffic_flow_controls(CAPTURE_RESULT, TrafficFlowControls())

    assert result == CAPTURE_RESULT
    assert result is not CAPTURE_RESULT


def test_controls_compose_display_filter_query_sort_and_metadata_scrubbing(
):
    controls = TrafficFlowControls(
        display_filter="protocol == tcp and bytes >= 400",
        ip_address="10.0.0.10",
        min_bytes=1000,
        sort_by="bytes",
        limit=1,
    )

    result = apply_traffic_flow_controls(CAPTURE_RESULT, controls)

    assert result["flow_count"] == 1
    assert [flow["flow_id"] for flow in result["flows"]] == ["flow-https"]
    assert "payload" not in result["flows"][0]
    assert result["conversations"] == [{"legacy": True}]
    assert result["flow_analysis"] == {
        "applied": True,
        "input_flow_count": 3,
        "matched_flow_count": 1,
        "display_filter": "protocol == tcp and bytes >= 400",
        "sort_by": "bytes",
        "limit": 1,
    }


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
