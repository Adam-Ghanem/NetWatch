from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Any

from traffic_capture import CaptureFilter, parse_ethernet_frame, summarize_capture

MAX_PCAP_BYTES = 32 * 1024 * 1024
MAX_PCAP_PACKETS = 5_000
MAX_CAPTURED_FRAME_BYTES = 262_144
LINKTYPE_ETHERNET = 1
_GLOBAL_HEADER_BYTES = 24
_RECORD_HEADER_BYTES = 16
_MAGIC_FORMATS: dict[bytes, tuple[str, float]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
}


def _pcap_header(data: bytes) -> tuple[str, float, int, str]:
    if len(data) < _GLOBAL_HEADER_BYTES:
        raise ValueError("PCAP header is truncated.")
    format_info = _MAGIC_FORMATS.get(data[:4])
    if format_info is None:
        raise ValueError("Unsupported PCAP magic; classic PCAP input is required.")
    byte_order, timestamp_scale = format_info
    major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack_from(
        f"{byte_order}HHIIII", data, 4
    )
    if (major, minor) != (2, 4):
        raise ValueError(f"Unsupported PCAP version {major}.{minor}; version 2.4 is required.")
    if linktype != LINKTYPE_ETHERNET:
        raise ValueError("Only Ethernet (LINKTYPE_ETHERNET) PCAP files are supported.")
    if snaplen < 1 or snaplen > MAX_CAPTURED_FRAME_BYTES:
        raise ValueError("PCAP snapshot length is outside the supported safety bound.")
    return byte_order, timestamp_scale, linktype, f"{major}.{minor}"


def import_pcap_metadata(data: bytes, *, max_packets: int = 1_000) -> dict[str, Any]:
    """Parse bounded classic-PCAP Ethernet records without retaining frame payload bytes."""
    if max_packets < 1 or max_packets > MAX_PCAP_PACKETS:
        raise ValueError(f"PCAP packet limit must be between 1 and {MAX_PCAP_PACKETS}.")
    if len(data) > MAX_PCAP_BYTES:
        raise ValueError("PCAP input is too large; the maximum accepted size is 32 MiB.")

    byte_order, timestamp_scale, linktype, version = _pcap_header(data)
    offset = _GLOBAL_HEADER_BYTES
    records: list[dict[str, object]] = []
    packet_number = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    while offset < len(data) and packet_number < max_packets:
        if len(data) - offset < _RECORD_HEADER_BYTES:
            raise ValueError("PCAP packet record header is truncated.")
        seconds, fraction, included_length, original_length = struct.unpack_from(
            f"{byte_order}IIII", data, offset
        )
        offset += _RECORD_HEADER_BYTES
        if included_length > MAX_CAPTURED_FRAME_BYTES:
            raise ValueError("PCAP packet record exceeds the supported frame-size safety bound.")
        if included_length > original_length:
            raise ValueError("PCAP packet record has an invalid captured/original length pair.")
        if len(data) - offset < included_length:
            raise ValueError("PCAP packet record data is truncated.")

        frame = data[offset : offset + included_length]
        offset += included_length
        packet_number += 1
        timestamp = float(seconds) + (float(fraction) / timestamp_scale)
        captured_at = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        first_timestamp = timestamp if first_timestamp is None else first_timestamp
        last_timestamp = timestamp
        record = parse_ethernet_frame(frame, packet_number, captured_at=captured_at)
        if record is not None:
            records.append(record)

    if first_timestamp is None or last_timestamp is None:
        duration_seconds = 0
    else:
        duration_seconds = max(0, int(last_timestamp - first_timestamp))

    result = summarize_capture(
        records,
        interface="pcap",
        duration_seconds=duration_seconds,
        capture_filter=CaptureFilter(),
    )
    result.update(
        {
            "source": "pcap",
            "pcap_version": version,
            "linktype": linktype,
            "processed_records": packet_number,
            "truncated_by_limit": offset < len(data),
            "payload_retained": False,
        }
    )
    return result
