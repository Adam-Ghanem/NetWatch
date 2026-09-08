from __future__ import annotations

from typing import cast

from flow_analysis import summarize_conversations, summarize_flows


def _packet(flags: str, *, reverse: bool = False) -> dict[str, object]:
    source_ip, destination_ip = (
        ("10.0.0.20", "10.0.0.10") if reverse else ("10.0.0.10", "10.0.0.20")
    )
    source_port, destination_port = (443, 51000) if reverse else (51000, 443)
    return {
        "protocol": "TCP",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_flags": flags,
        "length_bytes": 60,
    }


def test_tcp_history_is_direction_aware_for_handshake_and_close():
    flow = summarize_flows(
        [
            _packet("SYN"),
            _packet("ACK,SYN", reverse=True),
            _packet("ACK"),
            _packet("ACK,FIN"),
            _packet("ACK,FIN", reverse=True),
        ]
    )[0]

    assert flow["tcp_history"] == [">S", "<SA", ">A", ">F", "<F"]
    assert flow["tcp_history_truncated"] is False
    assert flow["tcp_handshake_observed"] is True
    assert flow["tcp_termination"] == "graceful_close"
    conversation_rows = cast(
        list[dict[str, object]], summarize_conversations([flow])["conversations"]
    )
    assert conversation_rows[0]["tcp_history"] == [">S", "<SA", ">A", ">F", "<F"]
    assert conversation_rows[0]["tcp_handshake_observed"] is True
    assert conversation_rows[0]["tcp_termination"] == "graceful_close"


def test_tcp_reset_is_classified_without_claiming_graceful_close():
    flow = summarize_flows(
        [
            _packet("SYN"),
            _packet("ACK,SYN", reverse=True),
            _packet("ACK"),
            _packet("ACK,RST", reverse=True),
        ]
    )[0]

    assert flow["tcp_handshake_observed"] is True
    assert flow["tcp_termination"] == "reset"


def test_single_fin_is_partial_close_not_failure_claim():
    flow = summarize_flows(
        [
            _packet("SYN"),
            _packet("ACK,SYN", reverse=True),
            _packet("ACK"),
            _packet("ACK,FIN"),
        ]
    )[0]

    assert flow["tcp_handshake_observed"] is True
    assert flow["tcp_termination"] == "partial_close"


def test_midstream_tcp_capture_keeps_unknown_handshake_and_termination():
    flow = summarize_flows([_packet("ACK"), _packet("ACK", reverse=True)])[0]

    assert flow["tcp_handshake_observed"] is False
    assert flow["tcp_termination"] == "not_observed"


def test_tcp_history_is_bounded_without_affecting_packet_counters():
    flow = summarize_flows([_packet("ACK") for _ in range(40)])[0]
    history = cast(list[str], flow["tcp_history"])

    assert len(history) == 32
    assert flow["tcp_history_truncated"] is True
    assert flow["packets"] == 40


def test_udp_flow_has_empty_transport_history():
    flow = summarize_flows(
        [
            {
                "protocol": "UDP",
                "source_ip": "10.0.0.10",
                "destination_ip": "10.0.0.53",
                "source_port": 53000,
                "destination_port": 53,
                "length_bytes": 70,
            }
        ]
    )[0]

    assert flow["tcp_history"] == []
    assert flow["tcp_history_truncated"] is False
    assert flow["tcp_handshake_observed"] is False
    assert flow["tcp_termination"] == "not_observed"
