from __future__ import annotations

import ipaddress
import struct

import pytest

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


def _simple_packet() -> bytes:
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
    frame = ethernet + ipv4 + udp
    return _block(3, struct.pack("<I", len(frame)) + frame)


def test_simple_packet_rejects_multi_interface_section() -> None:
    data = _section_header() + _interface_block() + _interface_block() + _simple_packet()

    with pytest.raises(ValueError, match="exactly one interface"):
        import_pcapng_bytes(data)
