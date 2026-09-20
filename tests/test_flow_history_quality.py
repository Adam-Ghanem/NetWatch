from __future__ import annotations

import pytest

from flow_history_quality import flow_history_quality_summary


def test_history_quality_partitions_valid_invalid_and_missing() -> None:
    summary = flow_history_quality_summary(
        [
            {"history": "ShADadFf"},
            {"history": ""},
            {"history": 123},
            {"history": None},
            {},
        ]
    )

    assert summary["flow_count"] == 5
    assert summary["history_flow_count"] == 1
    assert summary["invalid_history_flow_count"] == 2
    assert summary["missing_history_flow_count"] == 2
    assert summary["history_coverage_percent"] == 20.0
    assert summary["invalid_history_percent"] == 40.0
    assert summary["missing_history_percent"] == 40.0


def test_history_quality_reports_degradation_signals_once_per_flow() -> None:
    summary = flow_history_quality_summary(
        [
            {"history": "ShADadFf"},
            {"history": "ShgGtT"},
            {"history": "Cc"},
            {"history": "xX"},
            {"history": "iIqQ"},
            {"history": "gctx"},
        ]
    )

    assert summary["history_flow_count"] == 6
    assert summary["degraded_history_flow_count"] == 5
    assert summary["degraded_history_percent"] == pytest.approx(83.33)
    assert summary["capture_gap_flow_count"] == 2
    assert summary["partial_analysis_flow_count"] == 2
    assert summary["bad_checksum_flow_count"] == 2
    assert summary["retransmission_flow_count"] == 2
    assert summary["inconsistent_flow_count"] == 1


def test_history_quality_does_not_treat_normal_handshake_letters_as_degraded() -> None:
    summary = flow_history_quality_summary(
        [
            {"history": "ShADadFf"},
            {"history": "S"},
            {"history": "Sr"},
        ]
    )

    assert summary["degraded_history_flow_count"] == 0
    assert summary["degraded_history_percent"] == 0.0


def test_history_quality_is_bounded() -> None:
    summary = flow_history_quality_summary(
        [{"history": "g"}, {"history": "x"}, {"history": "c"}],
        flow_limit=2,
    )

    assert summary["flow_count"] == 2
    assert summary["capture_gap_flow_count"] == 1
    assert summary["partial_analysis_flow_count"] == 1
    assert summary["truncated"] is True


@pytest.mark.parametrize("flow_limit", [0, -1, True, 10_001])
def test_history_quality_rejects_invalid_limits(flow_limit: int) -> None:
    with pytest.raises(ValueError):
        flow_history_quality_summary([], flow_limit=flow_limit)
