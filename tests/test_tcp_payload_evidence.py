import pytest

from tcp_payload_evidence import tcp_payload_evidence_summary


def _record(source, destination, source_port, destination_port, length):
    return {
        "protocol": "TCP",
        "source_ip": source,
        "destination_ip": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_segment_length": length,
    }


def test_summarizes_bidirectional_payload_without_retaining_content():
    records = [
        _record("10.0.0.9", "10.0.0.2", 53000, 443, 120),
        _record("10.0.0.2", "10.0.0.9", 443, 53000, 800),
        _record("10.0.0.9", "10.0.0.2", 53000, 443, 0),
    ]

    summary = tcp_payload_evidence_summary(records)

    assert summary["tcp_record_count"] == 3
    assert summary["payload_segment_count"] == 2
    assert summary["payload_bytes"] == 920
    assert summary["originator_payload_bytes"] == 120
    assert summary["responder_payload_bytes"] == 800
    assert summary["bidirectional_payload_flow_count"] == 1
    assert summary["unidirectional_payload_flow_count"] == 0
    assert summary["payload_retained"] is False


def test_reports_missing_metadata_instead_of_guessing_from_frame_length():
    summary = tcp_payload_evidence_summary(
        [
            {
                "protocol": "TCP",
                "source_ip": "10.0.0.2",
                "destination_ip": "10.0.0.3",
                "source_port": 50000,
                "destination_port": 443,
                "length_bytes": 1514,
            }
        ]
    )

    assert summary["payload_bytes"] == 0
    assert summary["payload_segment_count"] == 0
    assert summary["metadata_missing_record_count"] == 1


def test_counts_unidirectional_payload_and_ignores_non_tcp_records():
    records = [
        _record("192.168.1.10", "192.168.1.20", 50000, 80, 50),
        {
            "protocol": "UDP",
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.1",
            "source_port": 53000,
            "destination_port": 53,
            "tcp_segment_length": 999,
        },
    ]

    summary = tcp_payload_evidence_summary(records)

    assert summary["record_count"] == 2
    assert summary["tcp_record_count"] == 1
    assert summary["payload_segment_percent"] == 100.0
    assert summary["unidirectional_payload_flow_count"] == 1


def test_record_limit_is_bounded_and_reports_truncation():
    records = [_record("10.0.0.1", "10.0.0.2", 50000, 443, 1) for _ in range(3)]

    summary = tcp_payload_evidence_summary(records, record_limit=2)

    assert summary["record_count"] == 2
    assert summary["payload_bytes"] == 2
    assert summary["truncated"] is True


@pytest.mark.parametrize("value", [0, 10_001, True])
def test_rejects_invalid_record_limits(value):
    with pytest.raises(ValueError):
        tcp_payload_evidence_summary([], record_limit=value)
