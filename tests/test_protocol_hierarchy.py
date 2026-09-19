from __future__ import annotations

import pytest

from protocol_hierarchy import protocol_hierarchy_summary


def test_protocol_hierarchy_builds_transport_and_application_rows() -> None:
    summary = protocol_hierarchy_summary(
        [
            {
                "protocol": "TCP",
                "service": "https",
                "packets": 10,
                "bytes": 1000,
            },
            {
                "protocol": "TCP",
                "service": "http",
                "packets": 5,
                "bytes": 500,
            },
            {
                "protocol": "UDP",
                "service": "dns",
                "packets": 2,
                "bytes": 100,
            },
        ]
    )

    assert summary["flow_count"] == 3
    assert summary["packet_count"] == 17
    assert summary["byte_count"] == 1600
    assert summary["privacy"] == {"payload_retained": False, "metadata_only": True}
    rows = summary["rows"]
    assert rows[0]["protocol"] == "tcp"
    assert rows[0]["service"] is None
    assert rows[0]["bytes"] == 1500
    assert rows[0]["flow_percent"] == pytest.approx(66.67)
    assert any(row["service"] == "https" and row["bytes"] == 1000 for row in rows)
    assert any(row["service"] == "dns" and row["level"] == "application" for row in rows)


def test_protocol_hierarchy_handles_unknown_and_invalid_counters() -> None:
    summary = protocol_hierarchy_summary(
        [{"protocol": "", "service": None, "packets": "bad", "bytes": -5}]
    )

    assert summary["packet_count"] == 0
    assert summary["byte_count"] == 0
    assert summary["rows"][0]["protocol"] == "unknown"
    assert any(row["service"] == "unknown" for row in summary["rows"])


def test_protocol_hierarchy_enforces_flow_and_row_bounds() -> None:
    flows = [
        {
            "protocol": "TCP",
            "service": f"svc-{index}",
            "packets": 1,
            "bytes": index + 1,
        }
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
