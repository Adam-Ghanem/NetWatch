from __future__ import annotations

import pytest

from flow_tcp_completeness import tcp_completeness_summary


def test_tcp_completeness_classifies_open_data_and_close_evidence() -> None:
    flows = [
        {
            "protocol": "TCP",
            "tcp_history": [">S", "<SA", ">A", ">D", "<D", ">F", "<F"],
        },
        {"protocol": "TCP", "tcp_history": [">S", "<SA", ">A", "<R"]},
        {"protocol": "TCP", "tcp_history": [">S"]},
        {"protocol": "UDP", "tcp_history": []},
    ]

    summary = tcp_completeness_summary(flows)

    assert summary["flow_count"] == 4
    assert summary["tcp_flow_count"] == 3
    assert summary["opening_complete_flow_count"] == 2
    assert summary["data_flow_count"] == 1
    assert summary["closing_observed_flow_count"] == 2
    assert summary["complete_with_data_flow_count"] == 1
    assert summary["complete_without_data_flow_count"] == 1
    assert summary["incomplete_flow_count"] == 1
    assert summary["complete_with_data_percent"] == pytest.approx(33.33)
    assert summary["complete_without_data_percent"] == pytest.approx(33.33)
    assert summary["incomplete_percent"] == pytest.approx(33.33)


def test_tcp_completeness_does_not_treat_partial_capture_as_risk() -> None:
    summary = tcp_completeness_summary(
        [{"protocol": "TCP", "tcp_history": [">D", "<A"]}]
    )

    assert summary["incomplete_flow_count"] == 1
    assert "risk" not in summary
    assert "attack" not in summary


def test_tcp_completeness_reports_missing_and_truncated_history() -> None:
    summary = tcp_completeness_summary(
        [
            {"protocol": "TCP"},
            {
                "protocol": "TCP",
                "tcp_history": [">S", "<SA", ">A", ">F"],
                "tcp_history_truncated": True,
            },
        ]
    )

    assert summary["missing_history_flow_count"] == 1
    assert summary["missing_history_percent"] == 50.0
    assert summary["history_truncated_flow_count"] == 1
    assert summary["history_truncated_percent"] == 50.0


def test_tcp_completeness_is_bounded() -> None:
    summary = tcp_completeness_summary(
        [
            {"protocol": "TCP", "tcp_history": [">S"]},
            {"protocol": "TCP", "tcp_history": [">S", "<SA", ">A", ">R"]},
        ],
        flow_limit=1,
    )

    assert summary["flow_count"] == 1
    assert summary["tcp_flow_count"] == 1
    assert summary["truncated"] is True


@pytest.mark.parametrize("flow_limit", [0, -1, True, 1001])
def test_tcp_completeness_rejects_invalid_limits(flow_limit: int) -> None:
    with pytest.raises(ValueError):
        tcp_completeness_summary([], flow_limit=flow_limit)
