import pytest

from flow_query import FlowQuery, query_flows

FLOWS = [
    {
        "flow_id": "https-flow",
        "protocol": "TCP",
        "service": "https",
        "state": "established",
        "bytes": 1200,
        "packets": 12,
        "duration_ms": 500,
        "last_seen": "2026-08-31T10:00:00.000+00:00",
        "originator": {"ip": "192.168.1.20", "port": 51000},
        "responder": {"ip": "192.168.1.1", "port": 443},
    },
    {
        "flow_id": "dns-flow",
        "protocol": "UDP",
        "service": "dns",
        "state": "datagram",
        "bytes": 300,
        "packets": 4,
        "duration_ms": 30,
        "last_seen": "2026-08-31T10:01:00.000+00:00",
        "originator": {"ip": "192.168.1.20", "port": 53000},
        "responder": {"ip": "1.1.1.1", "port": 53},
    },
    {
        "flow_id": "ssh-flow",
        "protocol": "TCP",
        "service": "ssh",
        "state": "opening",
        "bytes": 120,
        "packets": 2,
        "duration_ms": 5,
        "last_seen": "2026-08-31T09:59:00.000+00:00",
        "originator": {"ip": "192.168.1.30", "port": 52000},
        "responder": {"ip": "192.168.1.10", "port": 22},
    },
]


def test_filters_by_endpoint_protocol_service_state_and_minimum_bytes():
    result = query_flows(
        FLOWS,
        FlowQuery(
            ip_address="192.168.1.20",
            protocol="tcp",
            service="HTTPS",
            state="established",
            min_bytes=1000,
        ),
    )

    assert [flow["flow_id"] for flow in result] == ["https-flow"]


def test_default_sort_prefers_highest_byte_flow():
    result = query_flows(FLOWS)

    assert [flow["flow_id"] for flow in result] == [
        "https-flow",
        "dns-flow",
        "ssh-flow",
    ]


def test_recent_sort_and_limit_support_analyst_conversation_views():
    result = query_flows(FLOWS, FlowQuery(sort_by="recent", limit=2))

    assert [flow["flow_id"] for flow in result] == ["dns-flow", "https-flow"]


def test_packet_and_duration_sorting_are_deterministic():
    by_packets = query_flows(FLOWS, FlowQuery(sort_by="packets"))
    by_duration = query_flows(FLOWS, FlowQuery(sort_by="duration"))

    assert by_packets[0]["flow_id"] == "https-flow"
    assert by_duration[0]["flow_id"] == "https-flow"


def test_query_bounds_fail_closed():
    with pytest.raises(ValueError, match="cannot be negative"):
        query_flows(FLOWS, FlowQuery(min_bytes=-1))
    with pytest.raises(ValueError, match="between 1 and 1000"):
        query_flows(FLOWS, FlowQuery(limit=1001))
