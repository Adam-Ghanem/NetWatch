from __future__ import annotations

import pytest

from flow_correlation import CorrelationPolicy, correlate_flow_events


FLOWS = [
    {
        "flow_id": "flow-dns",
        "protocol": "UDP",
        "service": "dns",
        "originator": {"ip": "192.168.1.10", "port": 53000},
        "responder": {"ip": "192.168.1.1", "port": 53},
        "bytes": 180,
    },
    {
        "flow_id": "flow-web",
        "protocol": "TCP",
        "service": "https",
        "originator": {"ip": "192.168.1.10", "port": 54000},
        "responder": {"ip": "192.168.1.20", "port": 443},
        "bytes": 2048,
    },
]


def test_correlates_supported_protocol_metadata_by_flow_id_without_sensitive_fields():
    events = [
        {
            "flow_id": "flow-dns",
            "event_type": "dns",
            "timestamp": "2026-09-01T00:00:00+00:00",
            "metadata": {
                "query": "example.org",
                "qtype": "A",
                "rcode": "NOERROR",
                "answers": ["203.0.113.10"],
                "payload": "must-not-survive",
            },
        },
        {
            "flow_id": "flow-web",
            "event_type": "tls",
            "timestamp": "2026-09-01T00:00:01+00:00",
            "metadata": {
                "server_name": "example.org",
                "version": "TLSv1.3",
                "alpn": "h2",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "raw": "must-not-survive",
            },
        },
        {
            "flow_id": "flow-web",
            "event_type": "http",
            "timestamp": "2026-09-01T00:00:02+00:00",
            "metadata": {
                "method": "GET",
                "host": "example.org",
                "status_code": 200,
                "content_type": "text/html",
                "path": "/private?token=secret",
                "authorization": "Bearer secret",
                "cookie": "session=secret",
                "body": "must-not-survive",
            },
        },
        {
            "flow_id": "missing-flow",
            "event_type": "dns",
            "metadata": {"query": "ignored.example"},
        },
    ]

    result = correlate_flow_events(FLOWS, events)

    assert result["flow_count"] == 2
    assert result["event_count"] == 3
    dns = next(item for item in result["flows"] if item["flow_id"] == "flow-dns")
    web = next(item for item in result["flows"] if item["flow_id"] == "flow-web")
    assert dns["protocol_event_count"] == 1
    assert dns["protocol_events"][0]["metadata"] == {
        "answers": ["203.0.113.10"],
        "qtype": "A",
        "query": "example.org",
        "rcode": "NOERROR",
    }
    assert [event["event_type"] for event in web["protocol_events"]] == ["tls", "http"]
    assert web["protocol_events"][1]["metadata"] == {
        "content_type": "text/html",
        "host": "example.org",
        "method": "GET",
        "status_code": 200,
    }
    serialized = repr(result).lower()
    for forbidden in ("authorization", "cookie", "payload", "body", "token=secret", "raw"):
        assert forbidden not in serialized


def test_correlation_is_bounded_and_rejects_invalid_policy():
    with pytest.raises(ValueError, match="Flow correlation accepts at most 1 flows"):
        correlate_flow_events(FLOWS, [], policy=CorrelationPolicy(max_flows=1))

    with pytest.raises(ValueError, match="Protocol event limit must be between 1 and 50000"):
        CorrelationPolicy(max_events=0).validate()


def test_per_flow_event_limit_is_deterministic_and_supported_types_only():
    events = [
        {
            "flow_id": "flow-web",
            "event_type": "http",
            "timestamp": f"2026-09-01T00:00:0{index}+00:00",
            "metadata": {"method": "GET", "host": f"{index}.example.org"},
        }
        for index in range(3)
    ]
    events.append(
        {
            "flow_id": "flow-web",
            "event_type": "unknown",
            "timestamp": "2026-09-01T00:00:09+00:00",
            "metadata": {"data": "ignored"},
        }
    )

    result = correlate_flow_events(
        FLOWS,
        events,
        policy=CorrelationPolicy(max_events_per_flow=2),
    )
    web = next(item for item in result["flows"] if item["flow_id"] == "flow-web")

    assert web["protocol_event_count"] == 2
    assert [event["metadata"]["host"] for event in web["protocol_events"]] == [
        "0.example.org",
        "1.example.org",
    ]
    assert result["event_count"] == 2
