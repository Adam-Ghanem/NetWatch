from __future__ import annotations

from typing import cast

import pytest

from flow_investigation import build_flow_investigation
from flow_query import FlowQuery, query_flows
from traffic_flow_controls import TrafficFlowControls, apply_traffic_flow_controls

FLOWS = [
    {
        "flow_id": "reset-flow",
        "protocol": "TCP",
        "service": "https",
        "tcp_state": "reset",
        "tcp_termination": "reset",
        "bytes": 900,
        "packets": 8,
        "duration_ms": 120,
        "originator_packets": 5,
        "originator_bytes": 600,
        "responder_packets": 3,
        "responder_bytes": 300,
        "originator": {"ip": "10.0.0.10", "port": 51000},
        "responder": {"ip": "10.0.0.20", "port": 443},
    },
    {
        "flow_id": "partial-flow",
        "protocol": "TCP",
        "service": "ssh",
        "tcp_state": "closing",
        "tcp_termination": "partial_close",
        "bytes": 500,
        "packets": 5,
        "duration_ms": 80,
        "originator_packets": 3,
        "originator_bytes": 320,
        "responder_packets": 2,
        "responder_bytes": 180,
        "originator": {"ip": "10.0.0.30", "port": 52000},
        "responder": {"ip": "10.0.0.40", "port": 22},
    },
    {
        "flow_id": "graceful-flow",
        "protocol": "TCP",
        "service": "https",
        "tcp_state": "closing",
        "tcp_termination": "graceful_close",
        "bytes": 1200,
        "packets": 10,
        "duration_ms": 200,
        "originator_packets": 6,
        "originator_bytes": 700,
        "responder_packets": 4,
        "responder_bytes": 500,
        "originator": {"ip": "10.0.0.50", "port": 53000},
        "responder": {"ip": "10.0.0.60", "port": 443},
    },
]


def test_flow_query_pivots_exactly_on_tcp_termination_evidence():
    result = query_flows(FLOWS, FlowQuery(tcp_termination="RESET"))

    assert [flow["flow_id"] for flow in result] == ["reset-flow"]


def test_tcp_termination_query_rejects_unsupported_labels():
    with pytest.raises(ValueError, match="TCP termination must be one of"):
        query_flows(FLOWS, FlowQuery(tcp_termination="failed"))


def test_investigation_propagates_partial_close_pivot_to_all_views():
    result = build_flow_investigation(
        FLOWS,
        query=FlowQuery(tcp_termination="partial_close"),
    )
    conversations = cast(list[dict[str, object]], result["conversations"]["conversations"])

    assert result["matched_flow_count"] == 1
    assert [flow["flow_id"] for flow in result["flows"]] == ["partial-flow"]
    assert [row["flow_id"] for row in conversations] == ["partial-flow"]
    assert result["topology"]["edge_count"] == 1


def test_capture_controls_recompute_conversations_for_reset_pivot():
    capture = {
        "flows": FLOWS,
        "flow_count": len(FLOWS),
        "conversations": [],
    }

    result = apply_traffic_flow_controls(
        capture,
        TrafficFlowControls(tcp_termination="reset"),
    )

    assert result["flow_count"] == 1
    assert [flow["flow_id"] for flow in cast(list[dict[str, object]], result["flows"])] == [
        "reset-flow"
    ]
    conversations = cast(list[dict[str, object]], result["conversations"])
    assert [row["flow_id"] for row in conversations] == ["reset-flow"]
