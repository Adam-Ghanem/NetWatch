from __future__ import annotations

import pytest

from flow_connection_state import connection_state_summary


def test_connection_state_reports_operator_outcomes() -> None:
    states = [
        "SF",
        "S1",
        "S0",
        "REJ",
        "S2",
        "S3",
        "RSTO",
        "RSTR",
        "RSTOS0",
        "RSTRH",
        "SH",
        "SHR",
        "OTH",
    ]
    flows = [{"proto": "tcp", "conn_state": state} for state in states]
    flows.append({"proto": "udp", "conn_state": "SF"})

    summary = connection_state_summary(flows)

    assert summary["flow_count"] == 14
    assert summary["tcp_flow_count"] == 13
    assert summary["state_flow_count"] == 13
    assert summary["state_coverage_percent"] == 100.0
    assert summary["normal_close_flow_count"] == 1
    assert summary["established_unterminated_flow_count"] == 1
    assert summary["established_flow_count"] == 6
    assert summary["no_reply_flow_count"] == 1
    assert summary["rejected_flow_count"] == 1
    assert summary["reset_flow_count"] == 4
    assert summary["half_close_flow_count"] == 2
    assert summary["half_open_flow_count"] == 2
    assert summary["midstream_flow_count"] == 1


def test_connection_state_normalizes_case_and_whitespace() -> None:
    summary = connection_state_summary(
        [
            {"proto": " TCP ", "conn_state": " sf "},
            {"proto": "tcp", "conn_state": "rsto"},
            {"proto": "tcp", "conn_state": "rej"},
        ]
    )

    assert summary["normal_close_flow_count"] == 1
    assert summary["reset_flow_count"] == 1
    assert summary["rejected_flow_count"] == 1
    assert summary["normal_close_percent"] == pytest.approx(33.33)


def test_connection_state_tracks_missing_invalid_and_unknown_values() -> None:
    summary = connection_state_summary(
        [
            {"proto": "tcp"},
            {"proto": "tcp", "conn_state": None},
            {"proto": "tcp", "conn_state": ""},
            {"proto": "tcp", "conn_state": 7},
            {"proto": "tcp", "conn_state": "FUTURE_STATE"},
            {"proto": "udp"},
        ]
    )

    assert summary["tcp_flow_count"] == 5
    assert summary["missing_state_flow_count"] == 2
    assert summary["missing_state_percent"] == 40.0
    assert summary["invalid_state_flow_count"] == 2
    assert summary["invalid_state_percent"] == 40.0
    assert summary["unknown_state_flow_count"] == 1
    assert summary["unknown_state_percent"] == 20.0
    assert summary["state_flow_count"] == 1
    assert summary["state_coverage_percent"] == 20.0


def test_connection_state_is_descriptive_not_attack_scoring() -> None:
    summary = connection_state_summary(
        [
            {"proto": "tcp", "conn_state": "S0"},
            {"proto": "tcp", "conn_state": "REJ"},
            {"proto": "tcp", "conn_state": "OTH"},
        ]
    )

    assert "risk" not in summary
    assert "attack" not in summary
    assert summary["no_reply_flow_count"] == 1
    assert summary["rejected_flow_count"] == 1
    assert summary["midstream_flow_count"] == 1


def test_connection_state_is_bounded() -> None:
    summary = connection_state_summary(
        [
            {"proto": "tcp", "conn_state": "SF"},
            {"proto": "tcp", "conn_state": "S0"},
            {"proto": "tcp", "conn_state": "REJ"},
        ],
        flow_limit=2,
    )

    assert summary["flow_count"] == 2
    assert summary["tcp_flow_count"] == 2
    assert summary["truncated"] is True


@pytest.mark.parametrize("flow_limit", [0, -1, True, 10_001])
def test_connection_state_rejects_invalid_limits(flow_limit: int) -> None:
    with pytest.raises(ValueError):
        connection_state_summary([], flow_limit=flow_limit)
