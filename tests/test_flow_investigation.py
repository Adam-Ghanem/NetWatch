from flow_investigation import InvestigationLimits, build_flow_investigation
from flow_query import FlowQuery

FLOWS = [
    {
        "flow_id": "dns-1",
        "protocol": "UDP",
        "service": "dns",
        "originator": {"ip": "192.168.1.10", "port": 53000},
        "responder": {"ip": "192.168.1.1", "port": 53},
        "endpoint_a": {"ip": "192.168.1.1", "port": 53},
        "endpoint_b": {"ip": "192.168.1.10", "port": 53000},
        "packets": 4,
        "bytes": 420,
        "originator_packets": 2,
        "originator_bytes": 120,
        "responder_packets": 2,
        "responder_bytes": 300,
        "duration_ms": 18,
        "tcp_state": "-",
        "first_seen": "2026-09-01T04:00:00+00:00",
        "last_seen": "2026-09-01T04:00:00.018+00:00",
    },
    {
        "flow_id": "https-1",
        "protocol": "TCP",
        "service": "https",
        "originator": {"ip": "192.168.1.10", "port": 51000},
        "responder": {"ip": "203.0.113.20", "port": 443},
        "endpoint_a": {"ip": "192.168.1.10", "port": 51000},
        "endpoint_b": {"ip": "203.0.113.20", "port": 443},
        "packets": 12,
        "bytes": 9200,
        "originator_packets": 6,
        "originator_bytes": 1700,
        "responder_packets": 6,
        "responder_bytes": 7500,
        "duration_ms": 900,
        "tcp_state": "established",
        "first_seen": "2026-09-01T04:01:00+00:00",
        "last_seen": "2026-09-01T04:01:00.900+00:00",
    },
]


def test_investigation_scopes_all_views_to_flow_query() -> None:
    result = build_flow_investigation(
        FLOWS,
        query=FlowQuery(service="dns", limit=100),
        events=[
            {
                "flow_id": "dns-1",
                "event_type": "dns",
                "timestamp": "2026-09-01T04:00:00+00:00",
                "metadata": {
                    "query": "example.org",
                    "qtype": "A",
                    "answers": ["192.0.2.10"],
                    "payload": "must-not-leak",
                },
            },
            {
                "flow_id": "https-1",
                "event_type": "tls",
                "metadata": {"server_name": "example.org"},
            },
        ],
    )

    assert result["matched_flow_count"] == 1
    assert result["event_count"] == 1
    assert [flow["flow_id"] for flow in result["flows"]] == ["dns-1"]
    assert result["conversations"]["conversation_count"] == 1
    assert result["topology"]["edge_count"] == 1
    assert result["anomalies"] == []
    protocol_events = result["flows"][0]["protocol_events"]
    assert isinstance(protocol_events, list)
    first_event = protocol_events[0]
    assert isinstance(first_event, dict)
    metadata = first_event["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["query"] == "example.org"
    assert "payload" not in metadata
    assert result["payload_retained"] is False


def test_investigation_anomalies_are_scoped_and_explainable() -> None:
    flows: list[dict[str, object]] = []
    for index in range(20):
        flows.append(
            {
                "flow_id": f"fanout-{index}",
                "protocol": "TCP",
                "service": "https",
                "originator": {"ip": "192.168.1.50", "port": 50000 + index},
                "responder": {"ip": f"192.168.2.{index + 1}", "port": 443},
                "bytes": 1000,
                "originator_bytes": 500,
                "responder_bytes": 500,
                "tcp_state": "established",
            }
        )

    result = build_flow_investigation(flows, query=FlowQuery(ip_address="192.168.1.50", limit=100))

    assert len(result["anomalies"]) == 1
    finding = result["anomalies"][0]
    assert finding["signal"] == "high_fanout"
    assert finding["confidence"] == "high"
    assert finding["observed"] == 20
    assert finding["threshold"] == 20
    assert finding["evidence"] == {"unique_responder_count": 20, "flow_count": 20}
    assert len(finding["flow_ids"]) == 20
    assert finding["explanation"]


def test_investigation_applies_global_flow_bound_even_for_larger_query() -> None:
    result = build_flow_investigation(
        FLOWS,
        query=FlowQuery(limit=1000),
        limits=InvestigationLimits(flow_limit=1),
    )

    assert result["matched_flow_count"] == 1
    assert len(result["flows"]) == 1
    assert result["conversations"]["conversation_count"] == 1


def test_investigation_rejects_invalid_limits() -> None:
    try:
        build_flow_investigation(FLOWS, limits=InvestigationLimits(flow_limit=0))
    except ValueError as exc:
        assert "flow_limit" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("invalid investigation limit should fail closed")
