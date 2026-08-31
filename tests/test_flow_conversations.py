from __future__ import annotations

import flow_analysis


def test_conversation_stats_aggregate_endpoints_and_directional_totals():
    flows = [
        {
            "flow_id": "flow-https",
            "protocol": "TCP",
            "originator": {"ip": "192.168.1.10", "port": 51000},
            "responder": {"ip": "192.168.1.1", "port": 443},
            "service": "https",
            "packets": 8,
            "bytes": 1600,
            "originator_packets": 5,
            "originator_bytes": 900,
            "responder_packets": 3,
            "responder_bytes": 700,
            "first_seen": "2026-08-31T20:00:00+00:00",
            "last_seen": "2026-08-31T20:00:02+00:00",
            "duration_ms": 2000,
            "tcp_state": "established",
        },
        {
            "flow_id": "flow-dns",
            "protocol": "UDP",
            "originator": {"ip": "192.168.1.10", "port": 53000},
            "responder": {"ip": "192.168.1.53", "port": 53},
            "service": "dns",
            "packets": 2,
            "bytes": 220,
            "originator_packets": 1,
            "originator_bytes": 80,
            "responder_packets": 1,
            "responder_bytes": 140,
            "first_seen": "2026-08-31T20:00:01+00:00",
            "last_seen": "2026-08-31T20:00:01.050000+00:00",
            "duration_ms": 50,
            "tcp_state": "-",
        },
    ]

    result = flow_analysis.summarize_conversations(flows)

    assert result["conversation_count"] == 2
    assert result["endpoint_count"] == 3
    assert result["totals"] == {"packets": 10, "bytes": 1820}
    assert result["conversations"][0]["flow_id"] == "flow-https"
    assert result["conversations"][0]["source_to_destination_bytes"] == 900
    assert result["conversations"][0]["destination_to_source_bytes"] == 700
    assert result["endpoints"][0] == {
        "ip": "192.168.1.10",
        "packets": 10,
        "bytes": 1820,
        "sent_packets": 6,
        "sent_bytes": 980,
        "received_packets": 4,
        "received_bytes": 840,
        "conversation_count": 2,
    }


def test_conversation_stats_are_bounded_and_reject_invalid_limits():
    flows = [
        {
            "flow_id": f"flow-{index}",
            "protocol": "TCP",
            "originator": {"ip": "192.168.1.10", "port": 50000 + index},
            "responder": {"ip": f"192.168.1.{index + 20}", "port": 443},
            "service": "https",
            "packets": index + 1,
            "bytes": (index + 1) * 100,
            "originator_packets": index + 1,
            "originator_bytes": (index + 1) * 100,
            "responder_packets": 0,
            "responder_bytes": 0,
            "first_seen": "2026-08-31T20:00:00+00:00",
            "last_seen": "2026-08-31T20:00:00+00:00",
            "duration_ms": 0,
            "tcp_state": "opening",
        }
        for index in range(5)
    ]

    result = flow_analysis.summarize_conversations(flows, conversation_limit=2, endpoint_limit=2)

    assert [item["flow_id"] for item in result["conversations"]] == ["flow-4", "flow-3"]
    assert len(result["endpoints"]) == 2

    for invalid in (0, 1001):
        try:
            flow_analysis.summarize_conversations(flows, conversation_limit=invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid conversation limit must fail closed")
