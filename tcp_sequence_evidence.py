from __future__ import annotations

import struct
from collections import Counter
from typing import Iterable, Mapping

from ipv6_extension_headers import locate_ipv6_transport

_MAX_FINDINGS = 200
_SEQUENCE_MODULUS = 1 << 32
_SEQUENCE_HALF_RANGE = 1 << 31


def _transport_bounds(frame: bytes) -> tuple[int, int] | None:
    """Return a non-fragmented TCP transport offset and IP packet end."""
    if len(frame) < 14:
        return None
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if ether_type in {0x8100, 0x88A8}:
        if len(frame) < 18:
            return None
        ether_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18

    if ether_type == 0x0800:
        if len(frame) < offset + 20 or frame[offset] >> 4 != 4:
            return None
        header_length = (frame[offset] & 0x0F) * 4
        if header_length < 20 or len(frame) < offset + header_length:
            return None
        if frame[offset + 9] != 6:
            return None
        fragment_field = struct.unpack("!H", frame[offset + 6 : offset + 8])[0]
        if fragment_field & 0x3FFF:
            return None
        total_length = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
        if total_length < header_length:
            return None
        return offset + header_length, min(len(frame), offset + total_length)

    if ether_type == 0x86DD:
        if len(frame) < offset + 40 or frame[offset] >> 4 != 6:
            return None
        payload_length = struct.unpack("!H", frame[offset + 4 : offset + 6])[0]
        location = locate_ipv6_transport(
            frame,
            ipv6_offset=offset,
            next_header=frame[offset + 6],
        )
        if (
            not location.complete
            or location.protocol_number != 6
            or location.fragmented
        ):
            return None
        return location.transport_offset, min(len(frame), offset + 40 + payload_length)

    return None


def extract_tcp_sequence_metadata(frame: bytes) -> dict[str, int] | None:
    """Extract bounded TCP sequence metadata without retaining payload bytes."""
    bounds = _transport_bounds(frame)
    if bounds is None:
        return None
    transport_offset, packet_end = bounds
    if packet_end < transport_offset + 20 or len(frame) < transport_offset + 20:
        return None

    source_port, destination_port, sequence, acknowledgement = struct.unpack(
        "!HHII", frame[transport_offset : transport_offset + 12]
    )
    header_length = (frame[transport_offset + 12] >> 4) * 4
    if header_length < 20 or transport_offset + header_length > packet_end:
        return None

    flags = frame[transport_offset + 13]
    segment_length = max(0, packet_end - transport_offset - header_length)
    sequence_advance = segment_length + int(bool(flags & 0x02)) + int(bool(flags & 0x01))
    return {
        "tcp_sequence": sequence,
        "tcp_ack": acknowledgement,
        "tcp_segment_length": segment_length,
        "tcp_sequence_advance": sequence_advance,
        "tcp_source_port": source_port,
        "tcp_destination_port": destination_port,
    }


def _int_value(value: object) -> int | None:
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return None
    return number if 0 <= number < _SEQUENCE_MODULUS else None


def summarize_tcp_sequence_evidence(
    records: Iterable[Mapping[str, object]],
    *,
    finding_limit: int = _MAX_FINDINGS,
) -> dict[str, object]:
    """Summarize capture-visible TCP sequence discontinuities conservatively.

    Findings describe only observed capture ordering. A sequence gap can result from
    capture loss, mid-stream collection, or network behavior; an overlap can also be
    caused by reordering or retransmission. This function never labels either cause.
    """
    if finding_limit < 1 or finding_limit > _MAX_FINDINGS:
        raise ValueError(f"TCP sequence finding limit must be between 1 and {_MAX_FINDINGS}.")

    expected_by_direction: dict[tuple[str, int, str, int], int] = {}
    findings: list[dict[str, object]] = []
    counts: Counter[str] = Counter()
    observed_segments = 0

    for record in records:
        if str(record.get("protocol") or "").upper() != "TCP":
            continue
        sequence = _int_value(record.get("tcp_sequence"))
        advance = _int_value(record.get("tcp_sequence_advance"))
        source_port = _int_value(record.get("source_port"))
        destination_port = _int_value(record.get("destination_port"))
        source_ip = str(record.get("source_ip") or "")
        destination_ip = str(record.get("destination_ip") or "")
        if (
            sequence is None
            or advance is None
            or source_port is None
            or destination_port is None
            or not source_ip
            or not destination_ip
        ):
            continue

        observed_segments += 1
        direction = (source_ip, source_port, destination_ip, destination_port)
        flags = str(record.get("tcp_flags") or "")
        if "SYN" in flags and "ACK" not in flags:
            expected_by_direction[direction] = (sequence + advance) % _SEQUENCE_MODULUS
            continue

        expected = expected_by_direction.get(direction)
        next_sequence = (sequence + advance) % _SEQUENCE_MODULUS
        if expected is None:
            expected_by_direction[direction] = next_sequence
            continue

        forward = (sequence - expected) % _SEQUENCE_MODULUS
        if forward == 0:
            expected_by_direction[direction] = next_sequence
            continue

        if forward < _SEQUENCE_HALF_RANGE:
            evidence_type = "sequence_gap"
            offset_bytes = forward
            expected_by_direction[direction] = next_sequence
        else:
            evidence_type = "sequence_overlap"
            offset_bytes = (expected - sequence) % _SEQUENCE_MODULUS
            if advance > offset_bytes:
                expected_by_direction[direction] = next_sequence

        counts[evidence_type] += 1
        if len(findings) < finding_limit:
            findings.append(
                {
                    "type": evidence_type,
                    "packet_number": record.get("number"),
                    "captured_at": record.get("captured_at"),
                    "source_ip": source_ip,
                    "source_port": source_port,
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "observed_sequence": sequence,
                    "expected_sequence": expected,
                    "offset_bytes": offset_bytes,
                }
            )

    finding_count = sum(counts.values())
    return {
        "observed_tcp_segments": observed_segments,
        "finding_count": finding_count,
        "findings_truncated": finding_count > len(findings),
        "counts": {
            "sequence_gap": counts["sequence_gap"],
            "sequence_overlap": counts["sequence_overlap"],
        },
        "findings": findings,
        "interpretation": (
            "Capture-visible sequence discontinuities are evidence, not root-cause claims. "
            "Gaps may reflect capture loss or mid-stream collection; overlaps may reflect "
            "reordering or retransmission."
        ),
        "payload_retained": False,
    }
