from __future__ import annotations

import pytest

from protocol_hierarchy import protocol_hierarchy_summary


def test_protocol_hierarchy_builds_transport_and_application_rows() -> None:
    summary = protocol_hierarchy_summary(
        [
            {"protocol": "TCP", "service": "https", "packets": 10, "bytes": 1000},
            {"protocol": "TCP", "service": "http", "packets": 5, "bytes": 500},
            {"protocol": "UDP", "service": "dns", "packets": 2, "bytes": 100},
        ]
    )

    assert summary["flow_count"] == 3
    assert summary["packet_count"] == 17
    assert summary["byte_count"] == 1600
    assert summary["service_identified_flow_count"] == 3
    assert summary["service_unknown_flow_count"] == 0
    assert summary["service_identification_percent"] == 100.0
    assert summary["privacy"] == {"payload_retained": False, "metadata_only": True}
    rows = summary["rows"]
    assert rows[0]["protocol"] == "tcp"
    assert rows[0]["service"] is None
    assert rows[0]["bytes"] == 1500
    assert rows[0]["flow_percent"] == pytest.approx(66.67)
    assert any(row["service"] == "https" and row["bytes"] == 1000 for row in rows)
    assert any(row["service"] == "dns" and row["level"] == "application" for row in rows)


def test_protocol_hierarchy_preserves_directional_traffic_balance() -> None:
    summary = protocol_hierarchy_summary(
        [
            {
                "protocol": "TCP",
                "service": "https",
                "packets": 10,
                "bytes": 1000,
                "originator_packets": 4,
                "originator_bytes": 200,
                "responder_packets": 6,
                "responder_bytes": 800,
            },
            {
                "protocol": "TCP",
                "service": "https",
                "packets": 5,
                "bytes": 500,
                "originator_packets": 3,
                "originator_bytes": 300,
                "responder_packets": 2,
                "responder_bytes": 200,
            },
        ]
    )

    assert summary["originator_packet_count"] == 7
    assert summary["originator_byte_count"] == 500
    assert summary["responder_packet_count"] == 8
    assert summary["responder_byte_count"] == 1000
    transport = next(row for row in summary["rows"] if row["service"] is None)
    assert transport["originator_packets"] == 7
    assert transport["originator_bytes"] == 500
    assert transport["responder_packets"] == 8
    assert transport["responder_bytes"] == 1000
    assert transport["responder_byte_percent"] == pytest.approx(66.67)


def test_protocol_hierarchy_directionality_defaults_to_zero_when_absent() -> None:
    summary = protocol_hierarchy_summary(
        [{"protocol": "udp", "service": "dns", "packets": 2, "bytes": 100}]
    )

    assert summary["originator_byte_count"] == 0
    assert summary["responder_byte_count"] == 0
    assert all(row["responder_byte_percent"] == 0.0 for row in summary["rows"])


def test_protocol_hierarchy_tracks_unknown_service_coverage_without_fake_app_row() -> None:
    summary = protocol_hierarchy_summary(
        [
            {"protocol": "TCP", "service": "https", "packets": 4, "bytes": 400},
            {"protocol": "TCP", "service": None, "packets": 2, "bytes": 200},
            {"protocol": "UDP", "service": "unknown", "packets": 1, "bytes": 80},
            {"protocol": "UDP", "service": "-", "packets": 1, "bytes": 60},
        ]
    )

    assert summary["service_identified_flow_count"] == 1
    assert summary["service_unknown_flow_count"] == 3
    assert summary["service_identification_percent"] == 25.0
    assert not any(row["service"] == "unknown" for row in summary["rows"])
    assert [row["service"] for row in summary["rows"] if row["level"] == "application"] == ["https"]


def test_protocol_hierarchy_handles_unknown_and_invalid_counters() -> None:
    summary = protocol_hierarchy_summary(
        [{"protocol": "", "service": None, "packets": "bad", "bytes": -5}]
    )

    assert summary["packet_count"] == 0
    assert summary["byte_count"] == 0
    assert summary["rows"][0]["protocol"] == "unknown"
    assert summary["service_identified_flow_count"] == 0
    assert summary["service_unknown_flow_count"] == 1
    assert summary["service_identification_percent"] == 0.0
    assert all(row["level"] == "transport" for row in summary["rows"])


def test_protocol_hierarchy_enforces_flow_and_row_bounds() -> None:
    flows = [
        {"protocol": "TCP", "service": f"svc-{index}", "packets": 1, "bytes": index + 1}
        for index in range(5)
    ]
    summary = protocol_hierarchy_summary(flows, flow_limit=3, row_limit=2)

    assert summary["flow_count"] == 3
    assert len(summary["rows"]) == 2
    assert summary["truncated"] is True


def test_protocol_hierarchy_rejects_invalid_bounds() -> None:
    with pytest.raises(ValueError):
        protocol_hierarchy_summary([], flow_limit=0)
    with pytest.raises(ValueError):
        protocol_hierarchy_summary([], flow_limit=True)
    with pytest.raises(ValueError):
        protocol_hierarchy_summary([], row_limit=0)
