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
    assert summary["capture_gap_percent"] == pytest.approx(33.33)
    assert summary["partial_analysis_flow_count"] == 2
    assert summary["partial_analysis_percent"] == pytest.approx(33.33)
    assert summary["bad_checksum_flow_count"] == 2
    assert summary["bad_checksum_percent"] == pytest.approx(33.33)
    assert summary["retransmission_flow_count"] == 2
    assert summary["retransmission_percent"] == pytest.approx(33.33)
    assert summary["inconsistent_flow_count"] == 1
    assert summary["inconsistent_percent"] == pytest.approx(16.67)
    assert summary["zero_window_flow_count"] == 0
    assert summary["zero_window_percent"] == 0.0


def test_retransmissions_are_partitioned_by_connection_direction() -> None:
    summary = flow_history_quality_summary(
        [
            {"history": "T"},
            {"history": "t"},
            {"history": "TtTt"},
            {"history": "ShADadFf"},
            {"history": None},
        ]
    )

    assert summary["flow_count"] == 5
    assert summary["retransmission_flow_count"] == 3
    assert summary["retransmission_percent"] == 60.0
    assert summary["originator_retransmission_flow_count"] == 2
    assert summary["originator_retransmission_percent"] == 40.0
    assert summary["responder_retransmission_flow_count"] == 2
    assert summary["responder_retransmission_percent"] == 40.0
    assert summary["bidirectional_retransmission_flow_count"] == 1
    assert summary["bidirectional_retransmission_percent"] == 20.0
    assert summary["degraded_history_flow_count"] == 3


def test_history_quality_reports_zero_window_receiver_pressure() -> None:
    summary = flow_history_quality_summary(
        [
            {"history": "ShADadFf"},
            {"history": "ShwWadFf"},
            {"history": "W"},
            {"history": None},
        ]
    )

    assert summary["flow_count"] == 4
    assert summary["history_flow_count"] == 3
    assert summary["zero_window_flow_count"] == 2
    assert summary["zero_window_percent"] == 50.0
    assert summary["degraded_history_flow_count"] == 2
    assert summary["degraded_history_percent"] == 50.0


def test_zero_window_pressure_is_partitioned_by_connection_direction() -> None:
    summary = flow_history_quality_summary(
        [
            {"history": "w"},
            {"history": "W"},
            {"history": "wWwW"},
            {"history": "ShADadFf"},
            {"history": None},
        ]
    )

    assert summary["flow_count"] == 5
    assert summary["zero_window_flow_count"] == 3
    assert summary["zero_window_percent"] == 60.0
    assert summary["originator_zero_window_flow_count"] == 2
    assert summary["originator_zero_window_percent"] == 40.0
    assert summary["responder_zero_window_flow_count"] == 2
    assert summary["responder_zero_window_percent"] == 40.0
    assert summary["bidirectional_zero_window_flow_count"] == 1
    assert summary["bidirectional_zero_window_percent"] == 20.0


def test_zero_window_direction_matches_zeek_history_case_semantics() -> None:
    originator = flow_history_quality_summary([{"history": "W"}])
    responder = flow_history_quality_summary([{"history": "w"}])

    assert originator["originator_zero_window_flow_count"] == 1
    assert originator["responder_zero_window_flow_count"] == 0
    assert responder["originator_zero_window_flow_count"] == 0
    assert responder["responder_zero_window_flow_count"] == 1


def test_direction_flip_is_reported_as_provenance_not_degradation() -> None:
    summary = flow_history_quality_summary(
        [
            {"history": "Sh^ADadFf"},
            {"history": "^W"},
            {"history": "ShADadFf"},
            {"history": None},
        ]
    )

    assert summary["direction_flipped_flow_count"] == 2
    assert summary["direction_flipped_percent"] == 50.0
    assert summary["degraded_history_flow_count"] == 1
    assert summary["originator_zero_window_flow_count"] == 1


def test_tcp_resets_are_partitioned_by_direction_without_implying_degradation() -> None:
    summary = flow_history_quality_summary(
        [
            {"history": "ShADadR"},
            {"history": "Shr"},
            {"history": "RrRr"},
            {"history": "ShADadFf"},
            {"history": None},
        ]
    )

    assert summary["flow_count"] == 5
    assert summary["reset_flow_count"] == 3
    assert summary["reset_percent"] == 60.0
    assert summary["originator_reset_flow_count"] == 2
    assert summary["originator_reset_percent"] == 40.0
    assert summary["responder_reset_flow_count"] == 2
    assert summary["responder_reset_percent"] == 40.0
    assert summary["bidirectional_reset_flow_count"] == 1
    assert summary["bidirectional_reset_percent"] == 20.0
    assert summary["degraded_history_flow_count"] == 0


def test_history_signal_rates_use_all_observed_flows_as_denominator() -> None:
    summary = flow_history_quality_summary(
        [
            {"history": "g"},
            {"history": "ShADadFf"},
            {"history": None},
            {"history": ""},
        ]
    )

    assert summary["flow_count"] == 4
    assert summary["history_flow_count"] == 2
    assert summary["capture_gap_flow_count"] == 1
    assert summary["capture_gap_percent"] == 25.0


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
    assert summary["capture_gap_percent"] == 0.0
    assert summary["partial_analysis_percent"] == 0.0
    assert summary["bad_checksum_percent"] == 0.0
    assert summary["retransmission_percent"] == 0.0
    assert summary["originator_retransmission_percent"] == 0.0
    assert summary["responder_retransmission_percent"] == 0.0
    assert summary["bidirectional_retransmission_percent"] == 0.0
    assert summary["inconsistent_percent"] == 0.0
    assert summary["direction_flipped_percent"] == 0.0
    assert summary["reset_percent"] == pytest.approx(33.33)
    assert summary["originator_reset_percent"] == 0.0
    assert summary["responder_reset_percent"] == pytest.approx(33.33)
    assert summary["bidirectional_reset_percent"] == 0.0
    assert summary["zero_window_percent"] == 0.0
    assert summary["originator_zero_window_percent"] == 0.0
    assert summary["responder_zero_window_percent"] == 0.0
    assert summary["bidirectional_zero_window_percent"] == 0.0


def test_history_quality_is_bounded() -> None:
    summary = flow_history_quality_summary(
        [{"history": "g"}, {"history": "x"}, {"history": "c"}],
        flow_limit=2,
    )

    assert summary["flow_count"] == 2
    assert summary["capture_gap_flow_count"] == 1
    assert summary["capture_gap_percent"] == 50.0
    assert summary["partial_analysis_flow_count"] == 1
    assert summary["partial_analysis_percent"] == 50.0
    assert summary["truncated"] is True


@pytest.mark.parametrize("flow_limit", [0, -1, True, 10_001])
def test_history_quality_rejects_invalid_limits(flow_limit: int) -> None:
    with pytest.raises(ValueError):
        flow_history_quality_summary([], flow_limit=flow_limit)
