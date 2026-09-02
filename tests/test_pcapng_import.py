from __future__ import annotations

import ipaddress
import struct

import pytest

from pcapng_import import import_pcapng_bytes


def _ethernet_ipv4_udp_frame() -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    source = ipaddress.ip_address("10.0.0.10").packed
    destination = ipaddress.ip_address("10.0.0.53").packed
    udp = struct.pack("!HHHH", 53000, 53, 8, 0)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        source,
        destination,
    )
    return ethernet + ipv4 + udp


def _block(block_type: int, body: bytes, *, endian: str = "<") -> bytes:
    padding = b"\x00" * ((-len(body)) % 4)
    total_length = 12 + len(body) + len(padding)
    return (
        struct.pack(f"{endian}II", block_type, total_length)
        + body
        + padding
        + struct.pack(f"{endian}I", total_length)
    )


def _section_header(*, endian: str = "<") -> bytes:
    byte_order_magic = 0x1A2B3C4D
    body = struct.pack(f"{endian}IHHq", byte_order_magic, 1, 0, -1)
    return _block(0x0A0D0D0A, body, endian=endian)


def _interface_block(*, endian: str = "<", tsresol: int | None = None) -> bytes:
    body = struct.pack(f"{endian}HHI", 1, 0, 65_535)
    if tsresol is not None:
        body += struct.pack(f"{endian}HHB3x", 9, 1, tsresol)
        body += struct.pack(f"{endian}HH", 0, 0)
    return _block(1, body, endian=endian)


def _enhanced_packet(
    frame: bytes,
    *,
    timestamp_units: int,
    interface_id: int = 0,
    endian: str = "<",
) -> bytes:
    body = (
        struct.pack(
            f"{endian}IIIII",
            interface_id,
            timestamp_units >> 32,
            timestamp_units & 0xFFFFFFFF,
            len(frame),
            len(frame),
        )
        + frame
    )
    return _block(6, body, endian=endian)


def test_imports_ethernet_enhanced_packet_as_metadata_only() -> None:
    frame = _ethernet_ipv4_udp_frame()
    timestamp_units = 1_700_000_000 * 1_000_000
    data = (
        _section_header()
        + _interface_block()
        + _enhanced_packet(frame, timestamp_units=timestamp_units)
    )

    result = import_pcapng_bytes(data)

    assert result["capture_format"] == "pcapng"
    assert result["payload_retained"] is False
    assert result["captured_packets"] == 1
    assert result["processed_packets"] == 1
    assert result["section_count"] == 1
    assert result["interface_count"] == 1
    packet = result["packets"][0]
    assert packet["protocol"] == "UDP"
    assert packet["source_ip"] == "10.0.0.10"
    assert packet["destination_ip"] == "10.0.0.53"
    assert packet["source_port"] == 53000
    assert packet["destination_port"] == 53
    assert str(packet["captured_at"]).startswith("2023-11-14T22:13:20")
    assert frame.hex() not in str(result)


def test_honors_binary_timestamp_resolution() -> None:
    frame = _ethernet_ipv4_udp_frame()
    data = (
        _section_header()
        + _interface_block(tsresol=0x8A)
        + _enhanced_packet(frame, timestamp_units=1024)
    )

    result = import_pcapng_bytes(data)

    assert str(result["packets"][0]["captured_at"]).startswith("1970-01-01T00:00:01")


def test_supports_big_endian_section() -> None:
    frame = _ethernet_ipv4_udp_frame()
    data = (
        _section_header(endian=">")
        + _interface_block(endian=">")
        + _enhanced_packet(frame, timestamp_units=1_000_000, endian=">")
    )

    result = import_pcapng_bytes(data)

    assert result["captured_packets"] == 1
    assert str(result["packets"][0]["captured_at"]).startswith("1970-01-01T00:00:01")


def test_counts_interfaces_across_sections() -> None:
    frame = _ethernet_ipv4_udp_frame()
    data = (
        _section_header()
        + _interface_block()
        + _enhanced_packet(frame, timestamp_units=1)
        + _section_header(endian=">")
        + _interface_block(endian=">")
        + _enhanced_packet(frame, timestamp_units=1, endian=">")
    )

    result = import_pcapng_bytes(data)

    assert result["section_count"] == 2
    assert result["interface_count"] == 2
    assert result["processed_packets"] == 2


def test_rejects_unknown_interface_reference() -> None:
    data = (
        _section_header()
        + _interface_block()
        + _enhanced_packet(
            _ethernet_ipv4_udp_frame(),
            timestamp_units=1,
            interface_id=1,
        )
    )

    with pytest.raises(ValueError, match="unknown interface"):
        import_pcapng_bytes(data)


def test_rejects_truncated_block_and_invalid_packet_limit() -> None:
    with pytest.raises(ValueError, match="Packet limit"):
        import_pcapng_bytes(_section_header(), packet_limit=0)

    malformed = _section_header() + struct.pack("<II", 1, 20) + b"\x00\x00"
    with pytest.raises(ValueError, match="truncated"):
        import_pcapng_bytes(malformed)
