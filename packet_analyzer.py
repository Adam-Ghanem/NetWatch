from __future__ import annotations

import ipaddress
import math
import struct
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator

from config import COMMON_PORTS

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_SECTION = b"\x0a\x0d\x0d\x0a"
_LINK_TYPES = {
    1: "Ethernet",
    101: "Raw IP",
    113: "Linux cooked capture",
}
_SERVICE_PORTS = {
    **COMMON_PORTS,
    67: "DHCP",
    68: "DHCP",
    123: "NTP",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    1900: "SSDP",
    5353: "mDNS",
}
_DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}
_MAX_PACKET_TEXT = 240


class CaptureFormatError(ValueError):
    """The uploaded capture is unsupported, truncated, or structurally invalid."""


@dataclass(frozen=True)
class _CapturedPacket:
    timestamp: float | None
    captured_length: int
    original_length: int
    link_type: int
    payload: bytes


@dataclass(frozen=True)
class _DecodedPacket:
    source: str
    destination: str
    source_mac: str
    destination_mac: str
    protocol: str
    source_port: int | None
    destination_port: int | None
    service: str
    info: str


def _safe_packet_text(value: object, limit: int = _MAX_PACKET_TEXT) -> str:
    cleaned = "".join(
        character if character.isprintable() and character not in "\r\n\t" else " "
        for character in str(value or "")
    )
    return " ".join(cleaned.split())[:limit]


def _mac(payload: bytes) -> str:
    if len(payload) != 6:
        return ""
    return ":".join(f"{value:02X}" for value in payload)


def _ip(payload: bytes) -> str:
    try:
        return str(ipaddress.ip_address(payload))
    except ValueError:
        return ""


def _service_for_ports(source_port: int | None, destination_port: int | None) -> str:
    if destination_port is not None and destination_port in _SERVICE_PORTS:
        return _SERVICE_PORTS[destination_port]
    if source_port is not None and source_port in _SERVICE_PORTS:
        return _SERVICE_PORTS[source_port]
    return "Unknown"


def _dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    consumed = 0
    jumped = False
    visited: set[int] = set()
    for _ in range(32):
        if cursor >= len(payload) or cursor in visited:
            raise ValueError("Invalid DNS name")
        visited.add(cursor)
        length = payload[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(payload):
                raise ValueError("Truncated DNS pointer")
            pointer = ((length & 0x3F) << 8) | payload[cursor + 1]
            if not jumped:
                consumed += 2
            cursor = pointer
            jumped = True
            continue
        if length & 0xC0:
            raise ValueError("Unsupported DNS label")
        cursor += 1
        if not jumped:
            consumed += 1
        if length == 0:
            return _safe_packet_text(".".join(labels), 253), offset + consumed
        if length > 63 or cursor + length > len(payload):
            raise ValueError("Truncated DNS label")
        label = payload[cursor : cursor + length].decode("ascii", errors="replace")
        labels.append(_safe_packet_text(label, 63))
        cursor += length
        if not jumped:
            consumed += length
    raise ValueError("DNS compression depth exceeded")


def _dns_info(payload: bytes, include_dns_names: bool) -> str:
    if len(payload) < 12:
        return "DNS metadata (truncated)"
    flags, question_count = struct.unpack("!HH", payload[2:6])
    response = bool(flags & 0x8000)
    if response:
        return "DNS response"
    if not question_count:
        return "DNS query"
    try:
        name, offset = _dns_name(payload, 12)
        if offset + 4 > len(payload):
            raise ValueError("Truncated DNS question")
        query_type = struct.unpack("!H", payload[offset : offset + 2])[0]
    except (struct.error, ValueError):
        return "DNS query metadata (truncated)"
    if not include_dns_names:
        return f"DNS query {_DNS_TYPES.get(query_type, f'TYPE{query_type}')} (name hidden)"
    return _safe_packet_text(
        f"DNS query {_DNS_TYPES.get(query_type, f'TYPE{query_type}')} {name or '.'}"
    )


def _tcp_details(payload: bytes, offset: int) -> tuple[int | None, int | None, str]:
    if offset + 20 > len(payload):
        return None, None, "TCP metadata (truncated)"
    source_port, destination_port = struct.unpack("!HH", payload[offset : offset + 4])
    flags_value = payload[offset + 13]
    flags = [
        label
        for bit, label in (
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        )
        if flags_value & bit
    ]
    suffix = f" [{', '.join(flags)}]" if flags else ""
    return source_port, destination_port, f"{source_port} → {destination_port}{suffix}"


def _udp_details(
    payload: bytes,
    offset: int,
    *,
    include_dns_names: bool,
) -> tuple[int | None, int | None, str]:
    if offset + 8 > len(payload):
        return None, None, "UDP metadata (truncated)"
    source_port, destination_port, length = struct.unpack("!HHH", payload[offset : offset + 6])
    if source_port in {53, 5353} or destination_port in {53, 5353}:
        info = _dns_info(payload[offset + 8 :], include_dns_names)
    else:
        info = f"{source_port} → {destination_port} · {length} bytes"
    return source_port, destination_port, info


def _transport_details(
    payload: bytes,
    offset: int,
    protocol_number: int,
    *,
    include_dns_names: bool,
) -> tuple[str, int | None, int | None, str]:
    if protocol_number == 6:
        source_port, destination_port, info = _tcp_details(payload, offset)
        return "TCP", source_port, destination_port, info
    if protocol_number == 17:
        source_port, destination_port, info = _udp_details(
            payload,
            offset,
            include_dns_names=include_dns_names,
        )
        return "UDP", source_port, destination_port, info
    if protocol_number == 1:
        if offset + 2 <= len(payload):
            return "ICMP", None, None, f"ICMP type {payload[offset]}, code {payload[offset + 1]}"
        return "ICMP", None, None, "ICMP metadata (truncated)"
    if protocol_number == 58:
        if offset + 2 <= len(payload):
            return (
                "ICMPv6",
                None,
                None,
                (f"ICMPv6 type {payload[offset]}, code {payload[offset + 1]}"),
            )
        return "ICMPv6", None, None, "ICMPv6 metadata (truncated)"
    return f"IP protocol {protocol_number}", None, None, "Transport metadata unavailable"


def _decode_ipv4(
    payload: bytes,
    offset: int,
    source_mac: str,
    destination_mac: str,
    *,
    include_dns_names: bool,
) -> _DecodedPacket:
    if offset + 20 > len(payload):
        return _DecodedPacket(
            source_mac or "Unknown",
            destination_mac or "Unknown",
            source_mac,
            destination_mac,
            "IPv4",
            None,
            None,
            "Unknown",
            "IPv4 header truncated",
        )
    version_ihl = payload[offset]
    header_length = (version_ihl & 0x0F) * 4
    if version_ihl >> 4 != 4 or header_length < 20 or offset + header_length > len(payload):
        raise ValueError("Invalid IPv4 header")
    source = _ip(payload[offset + 12 : offset + 16])
    destination = _ip(payload[offset + 16 : offset + 20])
    protocol_number = payload[offset + 9]
    fragment = struct.unpack("!H", payload[offset + 6 : offset + 8])[0]
    fragment_offset = fragment & 0x1FFF
    if fragment_offset:
        protocol = "IPv4 fragment"
        source_port = destination_port = None
        info = f"Fragment offset {fragment_offset * 8} bytes"
    else:
        protocol, source_port, destination_port, info = _transport_details(
            payload,
            offset + header_length,
            protocol_number,
            include_dns_names=include_dns_names,
        )
    return _DecodedPacket(
        source or source_mac or "Unknown",
        destination or destination_mac or "Unknown",
        source_mac,
        destination_mac,
        protocol,
        source_port,
        destination_port,
        _service_for_ports(source_port, destination_port),
        info,
    )


def _ipv6_transport_offset(payload: bytes, offset: int) -> tuple[int, int, bool]:
    next_header = payload[offset + 6]
    cursor = offset + 40
    fragmented = False
    for _ in range(8):
        if next_header in {0, 43, 60}:
            if cursor + 2 > len(payload):
                raise ValueError("Truncated IPv6 extension header")
            header_length = (payload[cursor + 1] + 1) * 8
            next_header = payload[cursor]
            cursor += header_length
        elif next_header == 44:
            if cursor + 8 > len(payload):
                raise ValueError("Truncated IPv6 fragment header")
            fragment_value = struct.unpack("!H", payload[cursor + 2 : cursor + 4])[0]
            fragmented = bool(fragment_value & 0xFFF8)
            next_header = payload[cursor]
            cursor += 8
        elif next_header == 51:
            if cursor + 2 > len(payload):
                raise ValueError("Truncated IPv6 authentication header")
            header_length = (payload[cursor + 1] + 2) * 4
            next_header = payload[cursor]
            cursor += header_length
        else:
            return cursor, next_header, fragmented
        if cursor > len(payload):
            raise ValueError("IPv6 extension header exceeds packet")
    raise ValueError("Too many IPv6 extension headers")


def _decode_ipv6(
    payload: bytes,
    offset: int,
    source_mac: str,
    destination_mac: str,
    *,
    include_dns_names: bool,
) -> _DecodedPacket:
    if offset + 40 > len(payload):
        return _DecodedPacket(
            source_mac or "Unknown",
            destination_mac or "Unknown",
            source_mac,
            destination_mac,
            "IPv6",
            None,
            None,
            "Unknown",
            "IPv6 header truncated",
        )
    if payload[offset] >> 4 != 6:
        raise ValueError("Invalid IPv6 header")
    source = _ip(payload[offset + 8 : offset + 24])
    destination = _ip(payload[offset + 24 : offset + 40])
    transport_offset, protocol_number, fragmented = _ipv6_transport_offset(payload, offset)
    if fragmented:
        protocol = "IPv6 fragment"
        source_port = destination_port = None
        info = "Non-initial IPv6 fragment"
    else:
        protocol, source_port, destination_port, info = _transport_details(
            payload,
            transport_offset,
            protocol_number,
            include_dns_names=include_dns_names,
        )
    return _DecodedPacket(
        source or source_mac or "Unknown",
        destination or destination_mac or "Unknown",
        source_mac,
        destination_mac,
        protocol,
        source_port,
        destination_port,
        _service_for_ports(source_port, destination_port),
        info,
    )


def _decode_arp(
    payload: bytes,
    offset: int,
    source_mac: str,
    destination_mac: str,
) -> _DecodedPacket:
    if offset + 28 > len(payload):
        return _DecodedPacket(
            source_mac or "Unknown",
            destination_mac or "Unknown",
            source_mac,
            destination_mac,
            "ARP",
            None,
            None,
            "ARP",
            "ARP metadata (truncated)",
        )
    hardware_type, protocol_type, hardware_length, protocol_length, operation = struct.unpack(
        "!HHBBH", payload[offset : offset + 8]
    )
    if (
        hardware_type != 1
        or protocol_type != 0x0800
        or hardware_length != 6
        or protocol_length != 4
    ):
        return _DecodedPacket(
            source_mac or "Unknown",
            destination_mac or "Unknown",
            source_mac,
            destination_mac,
            "ARP",
            None,
            None,
            "ARP",
            f"ARP operation {operation}",
        )
    sender_mac = _mac(payload[offset + 8 : offset + 14])
    sender_ip = _ip(payload[offset + 14 : offset + 18])
    target_mac = _mac(payload[offset + 18 : offset + 24])
    target_ip = _ip(payload[offset + 24 : offset + 28])
    if operation == 1:
        info = f"Who has {target_ip}? Tell {sender_ip}"
    elif operation == 2:
        info = f"{sender_ip} is at {sender_mac}"
    else:
        info = f"ARP operation {operation}"
    return _DecodedPacket(
        sender_ip or sender_mac or source_mac or "Unknown",
        target_ip or target_mac or destination_mac or "Unknown",
        sender_mac or source_mac,
        target_mac or destination_mac,
        "ARP",
        None,
        None,
        "ARP",
        info,
    )


def _decode_network_payload(
    payload: bytes,
    offset: int,
    protocol_type: int,
    source_mac: str,
    destination_mac: str,
    *,
    include_dns_names: bool,
) -> _DecodedPacket:
    if protocol_type == 0x0800:
        return _decode_ipv4(
            payload,
            offset,
            source_mac,
            destination_mac,
            include_dns_names=include_dns_names,
        )
    if protocol_type == 0x86DD:
        return _decode_ipv6(
            payload,
            offset,
            source_mac,
            destination_mac,
            include_dns_names=include_dns_names,
        )
    if protocol_type == 0x0806:
        return _decode_arp(payload, offset, source_mac, destination_mac)
    return _DecodedPacket(
        source_mac or "Unknown",
        destination_mac or "Unknown",
        source_mac,
        destination_mac,
        "Ethernet",
        None,
        None,
        "Unknown",
        f"EtherType 0x{protocol_type:04X}",
    )


def _decode_frame(
    payload: bytes,
    link_type: int,
    *,
    include_dns_names: bool,
) -> _DecodedPacket:
    try:
        if link_type == 1:
            if len(payload) < 14:
                raise ValueError("Ethernet header truncated")
            destination_mac = _mac(payload[0:6])
            source_mac = _mac(payload[6:12])
            protocol_type = struct.unpack("!H", payload[12:14])[0]
            offset = 14
            for _ in range(2):
                if protocol_type not in {0x8100, 0x88A8, 0x9100}:
                    break
                if offset + 4 > len(payload):
                    raise ValueError("VLAN header truncated")
                protocol_type = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]
                offset += 4
            return _decode_network_payload(
                payload,
                offset,
                protocol_type,
                source_mac,
                destination_mac,
                include_dns_names=include_dns_names,
            )
        if link_type == 101:
            if not payload:
                raise ValueError("Raw IP packet is empty")
            version = payload[0] >> 4
            protocol_type = 0x0800 if version == 4 else (0x86DD if version == 6 else 0)
            return _decode_network_payload(
                payload,
                0,
                protocol_type,
                "",
                "",
                include_dns_names=include_dns_names,
            )
        if link_type == 113:
            if len(payload) < 16:
                raise ValueError("Linux cooked header truncated")
            address_length = min(struct.unpack("!H", payload[4:6])[0], 8)
            source_mac = _mac(payload[6 : 6 + min(address_length, 6)])
            protocol_type = struct.unpack("!H", payload[14:16])[0]
            return _decode_network_payload(
                payload,
                16,
                protocol_type,
                source_mac,
                "",
                include_dns_names=include_dns_names,
            )
    except (IndexError, struct.error, ValueError) as exc:
        return _DecodedPacket(
            "Unknown",
            "Unknown",
            "",
            "",
            "Malformed",
            None,
            None,
            "Unknown",
            _safe_packet_text(str(exc)),
        )
    return _DecodedPacket(
        "Unknown",
        "Unknown",
        "",
        "",
        "Unsupported",
        None,
        None,
        "Unknown",
        f"Unsupported link type {link_type}",
    )


def _parse_pcap(data: bytes, maximum_packets: int) -> tuple[list[_CapturedPacket], bool]:
    if len(data) < 24:
        raise CaptureFormatError("The PCAP global header is truncated.")
    magic = data[:4]
    if magic not in _PCAP_MAGIC:
        raise CaptureFormatError("The capture does not use a supported PCAP byte order.")
    endian, timestamp_scale = _PCAP_MAGIC[magic]
    try:
        version_major, version_minor, _, _, snap_length, link_type = struct.unpack(
            f"{endian}HHiIII", data[4:24]
        )
    except struct.error as exc:
        raise CaptureFormatError("The PCAP global header is invalid.") from exc
    if (version_major, version_minor) != (2, 4):
        raise CaptureFormatError("Only PCAP version 2.4 is supported.")
    if snap_length <= 0:
        raise CaptureFormatError("The PCAP snapshot length is invalid.")

    records: list[_CapturedPacket] = []
    offset = 24
    truncated = False
    while offset < len(data):
        if len(records) >= maximum_packets:
            truncated = True
            break
        if offset + 16 > len(data):
            raise CaptureFormatError("A PCAP packet header is truncated.")
        timestamp_seconds, timestamp_fraction, captured_length, original_length = struct.unpack(
            f"{endian}IIII", data[offset : offset + 16]
        )
        offset += 16
        if captured_length > len(data) - offset:
            raise CaptureFormatError("A PCAP packet extends beyond the uploaded file.")
        if timestamp_fraction >= timestamp_scale:
            timestamp_fraction = 0
        payload = data[offset : offset + captured_length]
        offset += captured_length
        records.append(
            _CapturedPacket(
                timestamp=float(timestamp_seconds) + (timestamp_fraction / timestamp_scale),
                captured_length=captured_length,
                original_length=max(captured_length, original_length),
                link_type=link_type,
                payload=payload,
            )
        )
    return records, truncated


def _pcapng_options(body: bytes, offset: int, endian: str) -> Iterator[tuple[int, bytes]]:
    while offset + 4 <= len(body):
        code, length = struct.unpack(f"{endian}HH", body[offset : offset + 4])
        offset += 4
        if code == 0:
            return
        if offset + length > len(body):
            return
        yield code, body[offset : offset + length]
        offset += (length + 3) & ~3


def _pcapng_resolution(options: Iterator[tuple[int, bytes]]) -> float:
    for code, value in options:
        if code != 9 or len(value) != 1:
            continue
        resolution = value[0]
        if resolution & 0x80:
            return math.pow(2.0, -(resolution & 0x7F))
        return math.pow(10.0, -resolution)
    return 0.000001


def _parse_pcapng(data: bytes, maximum_packets: int) -> tuple[list[_CapturedPacket], bool]:
    records: list[_CapturedPacket] = []
    interfaces: list[tuple[int, float, int]] = []
    offset = 0
    endian = ""
    truncated = False
    while offset < len(data):
        if offset + 12 > len(data):
            raise CaptureFormatError("A PCAPNG block header is truncated.")
        is_section = data[offset : offset + 4] == _PCAPNG_SECTION
        if is_section:
            byte_order = data[offset + 8 : offset + 12]
            if byte_order == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif byte_order == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise CaptureFormatError("The PCAPNG byte-order marker is invalid.")
        if not endian:
            raise CaptureFormatError("A PCAPNG section header must be the first block.")
        block_type, block_length = struct.unpack(f"{endian}II", data[offset : offset + 8])
        if block_length < 12 or block_length % 4 or offset + block_length > len(data):
            raise CaptureFormatError("A PCAPNG block length is invalid.")
        trailing_length = struct.unpack(
            f"{endian}I", data[offset + block_length - 4 : offset + block_length]
        )[0]
        if trailing_length != block_length:
            raise CaptureFormatError("A PCAPNG block length check failed.")
        body = data[offset + 8 : offset + block_length - 4]

        if block_type == 0x0A0D0D0A:
            if len(body) < 16:
                raise CaptureFormatError("The PCAPNG section header is truncated.")
            version_major, version_minor = struct.unpack(f"{endian}HH", body[4:8])
            if (version_major, version_minor) != (1, 0):
                raise CaptureFormatError("Only PCAPNG version 1.0 is supported.")
            interfaces = []
        elif block_type == 1:
            if len(body) < 8:
                raise CaptureFormatError("A PCAPNG interface block is truncated.")
            link_type = struct.unpack(f"{endian}H", body[0:2])[0]
            snap_length = struct.unpack(f"{endian}I", body[4:8])[0]
            resolution = _pcapng_resolution(_pcapng_options(body, 8, endian))
            interfaces.append((link_type, resolution, snap_length))
        elif block_type == 6:
            if len(records) >= maximum_packets:
                truncated = True
                break
            if len(body) < 20:
                raise CaptureFormatError("A PCAPNG enhanced packet block is truncated.")
            interface_id, timestamp_high, timestamp_low, captured_length, original_length = (
                struct.unpack(f"{endian}IIIII", body[:20])
            )
            if interface_id >= len(interfaces):
                raise CaptureFormatError("A PCAPNG packet references an unknown interface.")
            if 20 + captured_length > len(body):
                raise CaptureFormatError("A PCAPNG packet extends beyond its block.")
            link_type, resolution, snap_length = interfaces[interface_id]
            if snap_length and captured_length > snap_length:
                raise CaptureFormatError("A PCAPNG packet exceeds its interface snapshot length.")
            timestamp_value = (timestamp_high << 32) | timestamp_low
            records.append(
                _CapturedPacket(
                    timestamp=timestamp_value * resolution,
                    captured_length=captured_length,
                    original_length=max(captured_length, original_length),
                    link_type=link_type,
                    payload=body[20 : 20 + captured_length],
                )
            )
        elif block_type == 3:
            if len(records) >= maximum_packets:
                truncated = True
                break
            if len(body) < 4 or not interfaces:
                raise CaptureFormatError("A PCAPNG simple packet block is invalid.")
            original_length = struct.unpack(f"{endian}I", body[:4])[0]
            link_type, _, snap_length = interfaces[0]
            expected_length = min(original_length, snap_length) if snap_length else original_length
            captured_length = min(expected_length, len(body) - 4)
            records.append(
                _CapturedPacket(
                    timestamp=None,
                    captured_length=captured_length,
                    original_length=max(captured_length, original_length),
                    link_type=link_type,
                    payload=body[4 : 4 + captured_length],
                )
            )
        offset += block_length
    return records, truncated


def _timestamp_text(value: float | None) -> str:
    if value is None or value < 0:
        return ""
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat(timespec="microseconds")
    except (OSError, OverflowError, ValueError):
        return ""


def analyze_capture(
    data: bytes,
    *,
    maximum_bytes: int,
    maximum_packets: int,
    maximum_rows: int,
    include_dns_names: bool = False,
) -> dict[str, object]:
    """Analyze bounded capture metadata without returning or retaining packet payloads."""

    if not data:
        raise CaptureFormatError("The capture is empty.")
    if len(data) > maximum_bytes:
        raise CaptureFormatError("The capture exceeds the configured upload limit.")
    safe_packet_limit = max(1, int(maximum_packets))
    safe_row_limit = max(1, min(int(maximum_rows), safe_packet_limit))

    if data[:4] in _PCAP_MAGIC:
        capture_format = "pcap"
        records, truncated = _parse_pcap(data, safe_packet_limit)
    elif data[:4] == _PCAPNG_SECTION:
        capture_format = "pcapng"
        records, truncated = _parse_pcapng(data, safe_packet_limit)
    else:
        raise CaptureFormatError("Upload a supported .pcap or .pcapng capture.")

    protocol_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    endpoint_stats: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    conversation_stats: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0])
    rows: list[dict[str, object]] = []
    timestamps = [record.timestamp for record in records if record.timestamp is not None]
    first_timestamp = min(timestamps) if timestamps else None

    for index, record in enumerate(records, start=1):
        decoded = _decode_frame(
            record.payload,
            record.link_type,
            include_dns_names=include_dns_names,
        )
        protocol_stats[decoded.protocol][0] += 1
        protocol_stats[decoded.protocol][1] += record.original_length
        for endpoint in {decoded.source, decoded.destination} - {"", "Unknown"}:
            endpoint_stats[endpoint][0] += 1
            endpoint_stats[endpoint][1] += record.original_length
        left, right = sorted((decoded.source, decoded.destination))
        conversation_stats[(left, right, decoded.protocol)][0] += 1
        conversation_stats[(left, right, decoded.protocol)][1] += record.original_length

        if len(rows) >= safe_row_limit:
            continue
        relative_time = (
            round(record.timestamp - first_timestamp, 6)
            if record.timestamp is not None and first_timestamp is not None
            else None
        )
        rows.append(
            {
                "number": index,
                "time_seconds": relative_time,
                "timestamp_utc": _timestamp_text(record.timestamp),
                "source": decoded.source,
                "destination": decoded.destination,
                "source_mac": decoded.source_mac or "-",
                "destination_mac": decoded.destination_mac or "-",
                "protocol": decoded.protocol,
                "source_port": decoded.source_port,
                "destination_port": decoded.destination_port,
                "service": decoded.service,
                "length": record.original_length,
                "info": _safe_packet_text(decoded.info),
            }
        )

    protocol_rows = [
        {"protocol": protocol, "packets": values[0], "bytes": values[1]}
        for protocol, values in sorted(
            protocol_stats.items(),
            key=lambda item: (-item[1][0], item[0]),
        )
    ]
    endpoint_rows = [
        {"endpoint": endpoint, "packets": values[0], "bytes": values[1]}
        for endpoint, values in sorted(
            endpoint_stats.items(),
            key=lambda item: (-item[1][0], item[0]),
        )[:20]
    ]
    conversation_rows = [
        {
            "source": key[0],
            "destination": key[1],
            "protocol": key[2],
            "packets": values[0],
            "bytes": values[1],
        }
        for key, values in sorted(
            conversation_stats.items(),
            key=lambda item: (-item[1][0], item[0]),
        )[:20]
    ]
    duration = max(timestamps) - min(timestamps) if len(timestamps) >= 2 else 0.0
    link_types = sorted(
        {_LINK_TYPES.get(record.link_type, str(record.link_type)) for record in records}
    )
    rows_truncated = len(records) > len(rows)
    warnings = []
    if truncated:
        warnings.append("Packet processing stopped at the configured packet limit.")
    if rows_truncated:
        warnings.append(
            "The packet table is a bounded preview; summary counters use all analyzed packets."
        )
    if any(record.link_type not in _LINK_TYPES for record in records):
        warnings.append(
            "One or more link types are unsupported and were summarized without decoding."
        )

    return {
        "format": capture_format,
        "link_types": link_types,
        "packets_analyzed": len(records),
        "packets_returned": len(rows),
        "bytes_observed": sum(record.original_length for record in records),
        "duration_seconds": round(max(0.0, duration), 6),
        "truncated": truncated or rows_truncated,
        "payload_retained": False,
        "dns_names_included": bool(include_dns_names),
        "protocols": protocol_rows,
        "top_endpoints": endpoint_rows,
        "top_conversations": conversation_rows,
        "packets": rows,
        "warnings": warnings,
    }
