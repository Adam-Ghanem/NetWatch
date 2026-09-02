from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pcap_import import MAX_CAPTURED_FRAME_BYTES, MAX_PCAP_BYTES, MAX_PCAP_PACKETS
from traffic_capture import CaptureFilter, parse_ethernet_frame, summarize_capture

SECTION_HEADER_BLOCK = 0x0A0D0D0A
INTERFACE_DESCRIPTION_BLOCK = 0x00000001
ENHANCED_PACKET_BLOCK = 0x00000006
LINKTYPE_ETHERNET = 1
IF_TSRESOL_OPTION = 9
END_OF_OPTIONS = 0
MIN_BLOCK_BYTES = 12


@dataclass(frozen=True)
class _Interface:
    link_type: int
    timestamp_resolution: float


def _timestamp_resolution(option_value: int) -> float:
    if option_value & 0x80:
        return 2.0 ** -(option_value & 0x7F)
    return 10.0 ** -option_value


def _parse_idb_options(data: bytes, *, endian: str) -> float:
    resolution = 1e-6
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack(f"{endian}HH", data[offset : offset + 4])
        offset += 4
        if code == END_OF_OPTIONS:
            break
        padded_length = (length + 3) & ~3
        if offset + padded_length > len(data):
            raise ValueError("PCAPNG interface options are truncated.")
        value = data[offset : offset + length]
        if code == IF_TSRESOL_OPTION:
            if length != 1:
                raise ValueError("PCAPNG if_tsresol must contain exactly one byte.")
            resolution = _timestamp_resolution(value[0])
        offset += padded_length
    return resolution


def _decode_section_header(data: bytes, offset: int) -> tuple[str, int]:
    if offset + 28 > len(data):
        raise ValueError("PCAPNG section header is truncated.")
    magic = data[offset + 8 : offset + 12]
    if magic == b"\x4d\x3c\x2b\x1a":
        endian = "<"
    elif magic == b"\x1a\x2b\x3c\x4d":
        endian = ">"
    else:
        raise ValueError("PCAPNG section byte-order magic is invalid.")

    total_length = struct.unpack(f"{endian}I", data[offset + 4 : offset + 8])[0]
    if total_length < 28 or total_length % 4:
        raise ValueError("PCAPNG section header has an invalid block length.")
    if offset + total_length > len(data):
        raise ValueError("PCAPNG section header exceeds the available input.")
    trailer = struct.unpack(
        f"{endian}I", data[offset + total_length - 4 : offset + total_length]
    )[0]
    if trailer != total_length:
        raise ValueError("PCAPNG section header length fields do not match.")
    return endian, total_length


def import_pcapng_bytes(
    data: bytes,
    *,
    capture_filter: CaptureFilter | None = None,
    packet_limit: int = MAX_PCAP_PACKETS,
) -> dict[str, Any]:
    """Import bounded Ethernet PCAPNG packet metadata without retaining payloads."""

    if len(data) > MAX_PCAP_BYTES:
        raise ValueError(f"PCAPNG input exceeds the {MAX_PCAP_BYTES}-byte safety limit.")
    if packet_limit < 1 or packet_limit > MAX_PCAP_PACKETS:
        raise ValueError(f"Packet limit must be between 1 and {MAX_PCAP_PACKETS}.")
    if len(data) < 12 or data[:4] != b"\x0a\x0d\x0d\x0a":
        raise ValueError("Input is not a PCAPNG capture.")

    selected_filter = capture_filter or CaptureFilter()
    interfaces: list[_Interface] = []
    records: list[dict[str, object]] = []
    offset = 0
    endian = "<"
    sections = 0

    while offset < len(data) and len(records) < packet_limit:
        if offset + MIN_BLOCK_BYTES > len(data):
            raise ValueError("PCAPNG block header is truncated.")

        raw_type = data[offset : offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            endian, total_length = _decode_section_header(data, offset)
            interfaces = []
            sections += 1
            offset += total_length
            continue

        if sections == 0:
            raise ValueError("PCAPNG data must begin with a Section Header Block.")

        block_type, total_length = struct.unpack(
            f"{endian}II", data[offset : offset + 8]
        )
        if total_length < MIN_BLOCK_BYTES or total_length % 4:
            raise ValueError("PCAPNG block has an invalid total length.")
        block_end = offset + total_length
        if block_end > len(data):
            raise ValueError("PCAPNG block exceeds the available input.")
        trailer = struct.unpack(f"{endian}I", data[block_end - 4 : block_end])[0]
        if trailer != total_length:
            raise ValueError("PCAPNG block length fields do not match.")

        if block_type == INTERFACE_DESCRIPTION_BLOCK:
            if total_length < 20:
                raise ValueError("PCAPNG interface description block is truncated.")
            link_type = struct.unpack(f"{endian}H", data[offset + 8 : offset + 10])[0]
            options = data[offset + 16 : block_end - 4]
            interfaces.append(
                _Interface(
                    link_type=link_type,
                    timestamp_resolution=_parse_idb_options(options, endian=endian),
                )
            )
        elif block_type == ENHANCED_PACKET_BLOCK:
            if total_length < 32:
                raise ValueError("PCAPNG enhanced packet block is truncated.")
            interface_id, ts_high, ts_low, captured_length, _original_length = struct.unpack(
                f"{endian}IIIII", data[offset + 8 : offset + 28]
            )
            if interface_id >= len(interfaces):
                raise ValueError("PCAPNG packet references an unknown interface.")
            interface = interfaces[interface_id]
            if interface.link_type != LINKTYPE_ETHERNET:
                raise ValueError("Only Ethernet PCAPNG interfaces are supported.")
            if captured_length > MAX_CAPTURED_FRAME_BYTES:
                raise ValueError("PCAPNG captured frame exceeds the per-frame safety limit.")
            padded_length = (captured_length + 3) & ~3
            packet_end = offset + 28 + padded_length
            if packet_end > block_end - 4:
                raise ValueError("PCAPNG captured frame is truncated.")
            frame = data[offset + 28 : offset + 28 + captured_length]
            timestamp_units = (ts_high << 32) | ts_low
            captured_at = datetime.fromtimestamp(
                timestamp_units * interface.timestamp_resolution,
                tz=timezone.utc,
            )
            record = parse_ethernet_frame(
                frame,
                len(records) + 1,
                captured_at=captured_at,
            )
            if record is not None:
                from traffic_capture import packet_matches

                if packet_matches(record, selected_filter):
                    records.append(record)

        offset = block_end

    summary = summarize_capture(
        records,
        interface="pcapng-import",
        duration_seconds=0,
        capture_filter=selected_filter,
    )
    summary.update(
        {
            "capture_format": "pcapng",
            "section_count": sections,
            "interface_count": len(interfaces),
            "payload_retained": False,
        }
    )
    return summary
