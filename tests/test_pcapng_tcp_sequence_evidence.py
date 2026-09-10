from __future__ import annotations

import ipaddress
import struct

from pcapng_import import import_pcapng_bytes


def _block(block_type: int, body: bytes) -> bytes:
    padding = b"\x00" * ((-len(body)) % 4)
    total_length = 12 + len(body) + len(padding)
    return (
        struct.pack("<II", block_type, total_length)
        + body
        + padding
        + struct.pack("<I", total_length)
    )


def _section_header() -> bytes:
    return _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))


def _interface_block() -> bytes:
    return _block(1, struct.pack("<HHI", 1, 0, 65_535))


def _enhanced_packet(frame: bytes, timestamp_units: int) -> bytes:
    body = (
        struct.pack(
            "<IIIII",
            0,
            timestamp_units >> 32,
            timestamp_units & 0xFFFFFFFF,
            len(frame),
            len(frame),
        )
        + frame
    )
    return _block(6, body)


def _tcp_frame(*, sequence: int, payload: bytes = b"", flags: int = 0x10) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    source = ipaddress.ip_address("10.0.0.10").packed
    destination = ipaddress.ip_address("10.0.0.20").packed
    tcp = (
        struct.pack(
            "!HHIIBBHHH",
            50_000,
            443,
            sequence,
            1,
            5 << 4,
            flags,
            8192,
            0,
            0,
        )
        + payload
    )
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0,
        64,
        6,
        0,
        source,
        destination,
    )
    return ethernet + ipv4 + tcp


def _capture(frames: list[bytes]) -> bytes:
    data = _section_header() + _interface_block()
    for index, frame in enumerate(frames, start=1):
        data += _enhanced_packet(frame, index * 1_000_000)
    return data


def test_pcapng_import_exposes_tcp_sequence_metadata_and_gap_evidence() -> None:
    result = import_pcapng_bytes(
        _capture(
            [
                _tcp_frame(sequence=1000, flags=0x02),
                _tcp_frame(sequence=1001, payload=b"abc"),
                _tcp_frame(sequence=1008, payload=b"z"),
            ]
        )
    )

    packets = result["packets"]
    assert packets[0]["tcp_sequence"] == 1000
    assert packets[0]["tcp_sequence_advance"] == 1
    assert packets[1]["tcp_segment_length"] == 3
    assert packets[1]["tcp_ack"] == 1

    evidence = result["tcp_sequence_evidence"]
    assert evidence["observed_tcp_segments"] == 3
    assert evidence["finding_count"] == 1
    assert evidence["counts"] == {"sequence_gap": 1, "sequence_overlap": 0}
    assert evidence["findings"][0]["observed_sequence"] == 1008
    assert evidence["findings"][0]["expected_sequence"] == 1004
    assert evidence["findings"][0]["offset_bytes"] == 4
    assert evidence["payload_retained"] is False
    assert b"abc".hex() not in str(result)


def test_pcapng_import_reports_overlap_without_claiming_retransmission() -> None:
    result = import_pcapng_bytes(
        _capture(
            [
                _tcp_frame(sequence=2000, flags=0x02),
                _tcp_frame(sequence=2001, payload=b"abcdef"),
                _tcp_frame(sequence=2004, payload=b"xy"),
            ]
        )
    )

    evidence = result["tcp_sequence_evidence"]
    assert evidence["counts"] == {"sequence_gap": 0, "sequence_overlap": 1}
    assert evidence["findings"][0]["type"] == "sequence_overlap"
    assert evidence["findings"][0]["offset_bytes"] == 3
    assert "root-cause claims" in evidence["interpretation"]
    assert "retransmission" in evidence["interpretation"]
