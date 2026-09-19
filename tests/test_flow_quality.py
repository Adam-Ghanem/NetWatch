from __future__ import annotations

import pytest

from flow_quality import flow_quality_summary


def test_flow_quality_reports_independent_metadata_coverage() -> None:
    summary = flow_quality_summary(
        [
            {
                "service": "https",
                "duration": 1.25,
                "state": "closed",
                "originator_packets": 0,
                "originator_bytes": 0,
                "responder_packets": 4,
                "responder_bytes": 800,
            },
            {"service": "unknown", "duration": 0, "state": "established"},
            {"service": "dns"},
        ]
    )

    assert summary["flow_count"] == 3
    assert summary["directional_flow_count"] == 1
    assert summary["directional_coverage_percent"] == pytest.approx(33.33)
    assert summary["service_flow_count"] == 2
    assert summary["service_coverage_percent"] == pytest.approx(66.67)
    assert summary["duration_flow_count"] == 2
    assert summary["state_flow_count"] == 2
    assert summary["complete_flow_count"] == 1
    assert summary["complete_flow_percent"] == pytest.approx(33.33)


def test_flow_quality_treats_zero_directional_counters_as_observed() -> None:
    summary = flow_quality_summary(
        [
            {
                "originator_packets": 0,
                "originator_bytes": 0,
                "responder_packets": 0,
                "responder_bytes": 0,
            }
        ]
    )

    assert summary["directional_flow_count"] == 1
    assert summary["directional_coverage_percent"] == 100.0


def test_flow_quality_rejects_placeholders_and_missing_directional_fields() -> None:
    summary = flow_quality_summary(
        [
            {"service": "-", "duration": None, "state": "unknown"},
            {"service": "", "duration": "-", "state": ""},
            {"originator_packets": 1, "originator_bytes": 20},
        ]
    )

    assert summary["service_flow_count"] == 0
    assert summary["duration_flow_count"] == 0
    assert summary["state_flow_count"] == 0
    assert summary["directional_flow_count"] == 0
    assert summary["complete_flow_count"] == 0


def test_flow_quality_is_bounded() -> None:
    summary = flow_quality_summary([{"service": "dns"}] * 3, flow_limit=2)

    assert summary["flow_count"] == 2
    assert summary["truncated"] is True


def test_flow_quality_rejects_invalid_limit() -> None:
    with pytest.raises(ValueError):
        flow_quality_summary([], flow_limit=0)
    with pytest.raises(ValueError):
        flow_quality_summary([], flow_limit=True)
