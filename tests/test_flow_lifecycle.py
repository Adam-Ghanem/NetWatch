from __future__ import annotations

import pytest

from flow_lifecycle import flow_lifecycle_summary


def test_tcp_lifecycle_reports_handshake_and_close_evidence() -> None:
    summary = flow_lifecycle_summary(
        [
            {"proto": "tcp", "history": "ShADadFf"},
            {"proto": "tcp", "history": "ShADadR"},
            {"proto": "tcp", "history": "S"},
            {"proto": "tcp", "history": "Dd"},
            {"proto": "udp", "history": "Dd"},
        ]
    )

    assert summary["flow_count"] == 5
    assert summary["tcp_flow_count"] == 4
    assert summary["tcp_percent"] == 80.0
    assert summary["established_flow_count"] == 2
    assert summary["established_percent"] == 50.0
    assert summary["graceful_close_flow_count"] == 1
    assert summary["graceful_close_percent"] == 25.0
    assert summary["reset_close_flow_count"] == 1
    assert summary["reset_close_percent"] == 25.0
    assert summary["incomplete_handshake_flow_count"] == 1
    assert summary["incomplete_handshake_percent"] == 25.0
    assert summary["midstream_flow_count"] == 1
    assert summary["midstream_percent"] == 25.0


def test_lifecycle_does_not_treat_one_sided_fin_as_graceful_close() -> None:
    summary = flow_lifecycle_summary(
        [
            {"proto": "tcp", "history": "ShADadF"},
            {"proto": "tcp", "history": "ShADadf"},
            {"proto": "tcp", "history": "ShADadfF"},
        ]
    )

    assert summary["established_flow_count"] == 3
    assert summary["graceful_close_flow_count"] == 1
    assert summary["graceful_close_percent"] == pytest.approx(33.33)


def test_lifecycle_tracks_missing_and_invalid_tcp_history() -> None:
    summary = flow_lifecycle_summary(
        [
            {"proto": "tcp", "history": None},
            {"proto": "TCP"},
            {"proto": "tcp", "history": ""},
            {"proto": "tcp", "history": 123},
            {"proto": "udp", "history": None},
        ]
    )

    assert summary["tcp_flow_count"] == 4
    assert summary["missing_history_flow_count"] == 2
    assert summary["missing_history_percent"] == 40.0
    assert summary["invalid_history_flow_count"] == 2
    assert summary["invalid_history_percent"] == 40.0


def test_midstream_requires_tcp_activity_without_originator_syn() -> None:
    summary = flow_lifecycle_summary(
        [
            {"proto": "tcp", "history": "Dd"},
            {"proto": "tcp", "history": "Aad"},
            {"proto": "tcp", "history": "R"},
            {"proto": "tcp", "history": "S"},
        ]
    )

    assert summary["midstream_flow_count"] == 2
    assert summary["reset_close_flow_count"] == 1
    assert summary["incomplete_handshake_flow_count"] == 1


def test_lifecycle_is_bounded() -> None:
    summary = flow_lifecycle_summary(
        [
            {"proto": "tcp", "history": "ShADadFf"},
            {"proto": "tcp", "history": "S"},
            {"proto": "tcp", "history": "Dd"},
        ],
        flow_limit=2,
    )

    assert summary["flow_count"] == 2
    assert summary["tcp_flow_count"] == 2
    assert summary["truncated"] is True


@pytest.mark.parametrize("flow_limit", [0, -1, True, 10_001])
def test_lifecycle_rejects_invalid_limits(flow_limit: int) -> None:
    with pytest.raises(ValueError):
        flow_lifecycle_summary([], flow_limit=flow_limit)
