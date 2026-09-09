from __future__ import annotations

import socket
import struct

import pytest

from pcap_import import import_pcap_metadata
from tcp_sequence_evidence import (
    extract_tcp_sequence_metadata,
    summarize_tcp_sequence_evidence,
)


def _tcp_frame(
    sequence: int,
    payload: bytes = b"",
    *,
    acknowledgement: int = 1,
    flags: int = 0x10,
    fragment_field: int = 0,
) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    total_length = 20 + 20 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        fragment_field,
        64,
        6,
        0,
        socket.inet_aton("192.0.2.10"),
        socket.inet_aton("192.0.2.20"),
    )
    tcp = struct.pack(
        "!HHIIBBHHH",
        50000,
        443,
        sequence,
        acknowledgement,
        0x50,
        flags,
        65535,
        0,
        0,
    )
    return ethernet + ipv4 + tcp + payload


def _pcap(frames: list[bytes]) -> bytes:
    data = bytearray(b"\xd4\xc3\xb2\xa1")
    data.extend(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames, start=1):
        data.extend(struct.pack("<IIII", index, 0, len(frame), len(frame)))
        data.extend(frame)
    return bytes(data)


def test_extracts_sequence_ack_and_segment_length_without_payload_retention():
    metadata = extract_tcp_sequence_metadata(_tcp_frame(100, b"hello", acknowledgement=77))

    assert metadata == {
        "tcp_sequence": 100,
        "tcp_ack": 77,
        "tcp_segment_length": 5,
        "tcp_sequence_advance": 5,
        "tcp_source_port": 50000,
        "tcp_destination_port": 443,
    }


def test_fragmented_ipv4_tcp_is_not_used_for_sequence_evidence():
    assert extract_tcp_sequence_metadata(_tcp_frame(100, b"hello", fragment_field=0x2000)) is None


def test_sequence_summary_reports_gap_and_overlap_as_capture_evidence_only():
    records = [
        {
            "number": 1,
            "protocol": "TCP",
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "source_port": 50000,
            "destination_port": 443,
            "tcp_flags": "ACK",
            "tcp_sequence": 100,
            "tcp_sequence_advance": 3,
        },
        {
            "number": 2,
            "protocol": "TCP",
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "source_port": 50000,
            "destination_port": 443,
            "tcp_flags": "ACK",
            "tcp_sequence": 110,
            "tcp_sequence_advance": 2,
        },
        {
            "number": 3,
            "protocol": "TCP",
            "source_ip": "192.0.2.10",
            "destination_ip": "192.0.2.20",
            "source_port": 50000,
            "destination_port": 443,
            "tcp_flags": "ACK",
            "tcp_sequence": 111,
            "tcp_sequence_advance": 1,
        },
    ]

    summary = summarize_tcp_sequence_evidence(records)

    assert summary["counts"] == {"sequence_gap": 1, "sequence_overlap": 1}
    assert summary["finding_count"] == 2
    assert summary["findings"][0]["offset_bytes"] == 7
    assert summary["findings"][1]["offset_bytes"] == 1
    assert "not root-cause claims" in str(summary["interpretation"])
    assert summary["payload_retained"] is False


def test_classic_pcap_import_exposes_bounded_sequence_evidence():
    result = import_pcap_metadata(
        _pcap(
            [
                _tcp_frame(100, b"abc"),
                _tcp_frame(110, b"de"),
            ]
        )
    )

    evidence = result["tcp_sequence_evidence"]
    assert evidence["observed_tcp_segments"] == 2
    assert evidence["counts"]["sequence_gap"] == 1
    assert evidence["findings"][0]["offset_bytes"] == 7
    assert result["packets"][0]["tcp_sequence"] == 100
    assert result["packets"][0]["tcp_ack"] == 1
    assert result["payload_retained"] is False
    assert b"abc" not in str(result).encode()


def test_sequence_finding_limit_is_bounded():
    with pytest.raises(ValueError, match="finding limit"):
        summarize_tcp_sequence_evidence([], finding_limit=201)
