import json

import pytest

from flow_timeline import TimelinePolicy, build_flow_timeline


FLOWS = [
    {
        "flow_id": "dns-1",
        "protocol": "UDP",
        "service": "dns",
        "state": "observed",
        "originator": {"ip": "192.168.1.10", "port": 53000},
        "responder": {"ip": "192.168.1.1", "port": 53},
        "packets": 2,
        "bytes": 180,
        "first_seen": "2026-09-01T17:00:01+00:00",
        "last_seen": "2026-09-01T17:00:01.050+00:00",
        "duration_ms": 50,
        "payload": "must-not-leak",
    },
    {
        "flow_id": "https-1",
        "protocol": "TCP",
        "service": "https",
        "tcp_state": "established",
        "originator": {"ip": "192.168.1.10", "port": 54000},
        "responder": {"ip": "203.0.113.20", "port": 443},
        "packets": 8,
        "bytes": 2400,
        "first_seen": "2026-09-01T17:00:02+00:00",
        "last_seen": "2026-09-01T17:00:02.400+00:00",
        "duration_ms": 400,
        "raw": "must-not-leak",
    },
]

EVENTS = [
    {
        "flow_id": "https-1",
        "event_type": "http",
        "timestamp": "2026-09-01T17:00:02.200+00:00",
        "metadata": {
            "method": "GET",
            "host": "example.test",
            "status_code": 503,
            "path": "/private?token=secret",
            "authorization": "Bearer secret",
        },
    },
    {
        "flow_id": "dns-1",
        "event_type": "dns",
        "timestamp": "2026-09-01T17:00:01.020+00:00",
        "metadata": {
            "query": "example.test",
            "qtype": "A",
            "rcode": "NOERROR",
            "payload": "secret",
        },
    },
    {
        "flow_id": "missing",
        "event_type": "tls",
        "timestamp": "2026-09-01T17:00:00+00:00",
        "metadata": {"server_name": "ignored.test"},
    },
]


def test_timeline_orders_flow_and_protocol_events_by_timestamp():
    result = build_flow_timeline(FLOWS, EVENTS)

    assert result["flow_count"] == 2
    assert result["entry_count"] == 4
    assert result["payload_retained"] is False
    assert [entry["event_type"] for entry in result["entries"]] == [
        "flow",
        "dns",
        "flow",
        "http",
    ]
    assert [entry["flow_id"] for entry in result["entries"]] == [
        "dns-1",
        "dns-1",
        "https-1",
        "https-1",
    ]
    assert result["entries"][0]["state"] == "observed"
    assert result["entries"][2]["state"] == "established"


def test_timeline_keeps_only_safe_metadata():
    result = build_flow_timeline(FLOWS, EVENTS)
    serialized = json.dumps(result).lower()

    assert "must-not-leak" not in serialized
    assert "authorization" not in serialized
    assert "bearer secret" not in serialized
    assert "/private?token=secret" not in serialized
    assert '"payload"' not in serialized
    assert '"raw"' not in serialized

    http_entry = result["entries"][-1]
    assert http_entry["metadata"] == {
        "host": "example.test",
        "method": "GET",
        "status_code": 503,
    }


def test_timeline_is_bounded_and_validates_policy():
    result = build_flow_timeline(
        FLOWS,
        EVENTS,
        policy=TimelinePolicy(max_flows=2, max_events=3, max_entries=2),
    )
    assert result["entry_count"] == 2
    assert [entry["event_type"] for entry in result["entries"]] == ["flow", "dns"]

    with pytest.raises(ValueError, match="Timeline flow limit"):
        build_flow_timeline(FLOWS, EVENTS, policy=TimelinePolicy(max_flows=0))
    with pytest.raises(ValueError, match="at most 1 flows"):
        build_flow_timeline(FLOWS, EVENTS, policy=TimelinePolicy(max_flows=1))
