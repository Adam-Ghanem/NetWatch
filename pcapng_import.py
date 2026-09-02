from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pcap_import import (
    MAX_CAPTURED_FRAME_BYTES,
    MAX_PCAP_BYTES,
    MAX_PCAP_PACKETS,
)
from traffic_capture import (
    CaptureFilter,
    packet_matches,
    parse_ethernet_frame,
    summarize_capture,
)

SECTION_HEADER_BLOCK = 0x0A0D0D0A
INTERFACE_DESCRIPTION_BLOCK = 0x00000001
SIMPLE_PACKET_BLOCK = 0x00000003
INTERFACE_STATISTICS_BLOCK = 0x00000005
ENHANCED_PACKET_BLOCK = 0x00000006
LINKTYPE_ETHERNET = 1
IF_TSRESOL_OPTION = 9
IF_TSOFFSET_OPTION = 14
END_OF_OPTIONS = 0
ISB_STARTTIME_OPTION = 2
ISB_ENDTIME_OPTION = 3
ISB_IFRECV_OPTION = 4
ISB_IFDROP_OPTION = 5
ISB_FILTERACCEPT_OPTION = 6
ISB_OSDROP_OPTION = 7
ISB_USRDELIV_OPTION = 8
MIN_BLOCK_BYTES = 12
MAX_INTERFACE_STATISTICS = 1_000


@dataclass(frozen=True)
class _Interface:
    link_type: int
    snap_length: int
    timestamp_resolution: float
    timestamp_offset_seconds: int


def _timestamp_resolution(option_value: int) -> float:
    if option_value & 0x80:
        return 2.0 ** -(option_value & 0x7F)
    return 10.0**-option_value


def _parse_idb_options(data: bytes, *, endian: str) -> tuple[float, int]:
    resolution = 1e-6
    timestamp_offset_seconds = 0
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
        elif code == IF_TSOFFSET_OPTION:
            if length != 8:
                raise ValueError("PCAPNG if_tsoffset must contain exactly eight bytes.")
            timestamp_offset_seconds = struct.unpack(f"{endian}q", value)[0]
        offset += padded_length
    return resolution, timestamp_offset_seconds


def _parse_isb_options(data: bytes, *, endian: str) -> dict[str, int | None]:
    values: dict[str, int | None] = {
        "start_timestamp_units": None,
        "end_timestamp_units": None,
        "received_packets": None,
        "dropped_packets": None,
        "filter_accepted_packets": None,
        "os_dropped_packets": None,
        "user_delivered_packets": None,
    }
    option_names = {
        ISB_STARTTIME_OPTION: "start_timestamp_units",
        ISB_ENDTIME_OPTION: "end_timestamp_units",
        ISB_IFRECV_OPTION: "received_packets",
        ISB_IFDROP_OPTION: "dropped_packets",
        ISB_FILTERACCEPT_OPTION: "filter_accepted_packets",
        ISB_OSDROP_OPTION: "os_dropped_packets",
        ISB_USRDELIV_OPTION: "user_delivered_packets",
    }
    offset = 0
    seen: set[int] = set()
    while offset + 4 <= len(data):
        code, length = struct.unpack(f"{endian}HH", data[offset : offset + 4])
        offset += 4
        if code == END_OF_OPTIONS:
            break
        padded_length = (length + 3) & ~3
        if offset + padded_length > len(data):
            raise ValueError("PCAPNG interface statistics options are truncated.")
        if code in option_names:
            if code in seen:
                raise ValueError("PCAPNG interface statistics option is duplicated.")
            if length != 8:
                raise ValueError("PCAPNG interface statistics values must contain eight bytes.")
            seen.add(code)
            values[option_names[code]] = struct.unpack(f"{endian}Q", data[offset : offset + 8])[0]
        offset += padded_length
    return values


def _timestamp_from_units(units: int, interface: _Interface) -> str:
    return datetime.fromtimestamp(
        units * interface.timestamp_resolution + interface.timestamp_offset_seconds,
        tz=timezone.utc,
    ).isoformat(timespec="microseconds")


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
    trailer = struct.unpack(f"{endian}I", data[offset + total_length - 4 : offset + total_length])[
        0
    ]
    if trailer != total_length:
        raise ValueError("PCAPNG section header length fields do not match.")
    return endian, total_length


def _append_packet_record(
    records: list[dict[str, object]],
    *,
    frame: bytes,
    selected_filter: CaptureFilter,
    captured_at: datetime | None,
    timestamp_available: bool,
) -> None:
    record = parse_ethernet_frame(
        frame,
        len(records) + 1,
        captured_at=captured_at,
    )
    if record is None:
        return
    if not timestamp_available:
        record["captured_at"] = None
    record["timestamp_available"] = timestamp_available
    if packet_matches(record, selected_filter):
        records.append(record)


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
    interface_statistics: list[dict[str, object]] = []
    offset = 0
    endian = "<"
    sections = 0
    total_interfaces = 0
    processed_packets = 0
    enhanced_packet_count = 0
    simple_packet_count = 0

    while offset < len(data) and processed_packets < packet_limit:
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

        block_type, total_length = struct.unpack(f"{endian}II", data[offset : offset + 8])
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
            link_type, _reserved, snap_length = struct.unpack(
                f"{endian}HHI",
                data[offset + 8 : offset + 16],
            )
            options = data[offset + 16 : block_end - 4]
            timestamp_resolution, timestamp_offset_seconds = _parse_idb_options(
                options,
                endian=endian,
            )
            interfaces.append(
                _Interface(
                    link_type=link_type,
                    snap_length=snap_length,
                    timestamp_resolution=timestamp_resolution,
                    timestamp_offset_seconds=timestamp_offset_seconds,
                )
            )
            total_interfaces += 1
        elif block_type == INTERFACE_STATISTICS_BLOCK:
            if total_length < 24:
                raise ValueError("PCAPNG interface statistics block is truncated.")
            if len(interface_statistics) >= MAX_INTERFACE_STATISTICS:
                raise ValueError("PCAPNG interface statistics exceed the safety limit.")
            interface_id, ts_high, ts_low = struct.unpack(
                f"{endian}III", data[offset + 8 : offset + 20]
            )
            if interface_id >= len(interfaces):
                raise ValueError("PCAPNG statistics reference an unknown interface.")
            interface = interfaces[interface_id]
            values = _parse_isb_options(data[offset + 20 : block_end - 4], endian=endian)
            timestamp_units = (ts_high << 32) | ts_low
            row: dict[str, object] = {
                "section": sections,
                "interface_id": interface_id,
                "recorded_at": _timestamp_from_units(timestamp_units, interface),
            }
            start_units = values.pop("start_timestamp_units")
            end_units = values.pop("end_timestamp_units")
            row["capture_started_at"] = (
                _timestamp_from_units(start_units, interface) if start_units is not None else None
            )
            row["capture_ended_at"] = (
                _timestamp_from_units(end_units, interface) if end_units is not None else None
            )
            row.update(values)
            interface_statistics.append(row)
        elif block_type == ENHANCED_PACKET_BLOCK:
            processed_packets += 1
            enhanced_packet_count += 1
            if total_length < 32:
                raise ValueError("PCAPNG enhanced packet block is truncated.")
            (
                interface_id,
                ts_high,
                ts_low,
                captured_length,
                _original_length,
            ) = struct.unpack(f"{endian}IIIII", data[offset + 8 : offset + 28])
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
                timestamp_units * interface.timestamp_resolution
                + interface.timestamp_offset_seconds,
                tz=timezone.utc,
            )
            _append_packet_record(
                records,
                frame=frame,
                selected_filter=selected_filter,
                captured_at=captured_at,
                timestamp_available=True,
            )
        elif block_type == SIMPLE_PACKET_BLOCK:
            processed_packets += 1
            simple_packet_count += 1
            if total_length < 16:
                raise ValueError("PCAPNG simple packet block is truncated.")
            if not interfaces:
                raise ValueError("PCAPNG simple packet block requires interface 0.")
            if len(interfaces) != 1:
                raise ValueError(
                    "PCAPNG simple packet block requires exactly one interface in its section."
                )
            interface = interfaces[0]
            if interface.link_type != LINKTYPE_ETHERNET:
                raise ValueError("Only Ethernet PCAPNG interfaces are supported.")
            original_length = struct.unpack(f"{endian}I", data[offset + 8 : offset + 12])[0]
            captured_length = (
                original_length
                if interface.snap_length == 0
                else min(original_length, interface.snap_length)
            )
            if captured_length > MAX_CAPTURED_FRAME_BYTES:
                raise ValueError("PCAPNG captured frame exceeds the per-frame safety limit.")
            padded_length = (captured_length + 3) & ~3
            expected_total_length = 16 + padded_length
            if total_length != expected_total_length:
                raise ValueError(
                    "PCAPNG simple packet block length does not match interface SnapLen."
                )
            frame = data[offset + 12 : offset + 12 + captured_length]
            _append_packet_record(
                records,
                frame=frame,
                selected_filter=selected_filter,
                captured_at=None,
                timestamp_available=False,
            )

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
            "interface_count": total_interfaces,
            "processed_packets": processed_packets,
            "enhanced_packet_count": enhanced_packet_count,
            "simple_packet_count": simple_packet_count,
            "untimestamped_packets": simple_packet_count,
            "interface_statistics_count": len(interface_statistics),
            "interface_statistics": interface_statistics,
            "payload_retained": False,
        }
    )
    return summary
