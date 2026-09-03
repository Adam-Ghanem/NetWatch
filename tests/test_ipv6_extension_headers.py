import socket
import struct

import pytest

from ipv6_extension_headers import locate_ipv6_transport


def _ipv6_packet(next_header: int, payload: bytes) -> bytes:
    source = socket.inet_pton(socket.AF_INET6, "fd00::10")
    destination = socket.inet_pton(socket.AF_INET6, "fd00::20")
    header = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        next_header,
        64,
        source,
        destination,
    )
    return header + payload


def test_walks_options_and_routing_headers_to_tcp():
    hop_by_hop = bytes([43, 0]) + bytes(6)
    routing = bytes([6, 0]) + bytes(6)
    tcp = struct.pack(
        "!HHLLBBHHH",
        50_000,
        443,
        0,
        0,
        0x50,
        0x02,
        65_535,
        0,
        0,
    )
    packet = _ipv6_packet(0, hop_by_hop + routing + tcp)

    location = locate_ipv6_transport(packet, ipv6_offset=0, next_header=0)

    assert location.protocol_number == 6
    assert location.transport_offset == 56
    assert location.extension_headers == ("hop_by_hop", "routing")
    assert location.fragmented is False
    assert location.first_fragment is True
    assert location.complete is True
    assert location.findings == ()


def test_initial_fragment_can_reach_upper_layer_header():
    fragment = bytes([17, 0, 0, 1]) + (1234).to_bytes(4, "big")
    udp = struct.pack("!HHHH", 53_000, 53, 8, 0)
    packet = _ipv6_packet(44, fragment + udp)

    location = locate_ipv6_transport(packet, ipv6_offset=0, next_header=44)

    assert location.protocol_number == 17
    assert location.transport_offset == 48
    assert location.extension_headers == ("fragment",)
    assert location.fragmented is True
    assert location.first_fragment is True
    assert location.complete is True
    assert location.findings == ()


def test_non_initial_fragment_never_claims_transport_header():
    fragment_offset_one = 1 << 3
    fragment = bytes([6, 0]) + fragment_offset_one.to_bytes(2, "big") + (99).to_bytes(4, "big")
    packet = _ipv6_packet(44, fragment + b"not-a-tcp-header")

    location = locate_ipv6_transport(packet, ipv6_offset=0, next_header=44)

    assert location.protocol_number == 6
    assert location.fragmented is True
    assert location.first_fragment is False
    assert location.complete is True
    assert location.findings == ()


def test_truncated_extension_header_fails_closed():
    packet = _ipv6_packet(0, bytes([6, 2]) + bytes(6))

    location = locate_ipv6_transport(packet, ipv6_offset=0, next_header=0)

    assert location.extension_headers == ("hop_by_hop",)
    assert location.complete is False
    assert location.findings == ("invalid_extension_header_length",)


def test_extension_chain_limits_prevent_pathological_walks():
    destination_options = bytes([60, 0]) + bytes(6)
    packet = _ipv6_packet(60, destination_options * 3)

    location = locate_ipv6_transport(
        packet,
        ipv6_offset=0,
        next_header=60,
        max_extension_headers=2,
    )

    assert len(location.extension_headers) == 2
    assert location.complete is False
    assert location.findings == ("extension_header_limit_reached",)


def test_flags_hop_by_hop_when_it_is_not_first():
    routing = bytes([0, 0]) + bytes(6)
    hop_by_hop = bytes([6, 0]) + bytes(6)
    packet = _ipv6_packet(43, routing + hop_by_hop + bytes(20))

    location = locate_ipv6_transport(packet, ipv6_offset=0, next_header=43)

    assert location.extension_headers == ("routing", "hop_by_hop")
    assert location.complete is True
    assert location.findings == ("hop_by_hop_not_first",)


def test_flags_duplicate_hop_by_hop_and_fragment_headers():
    hop_one = bytes([0, 0]) + bytes(6)
    hop_two = bytes([44, 0]) + bytes(6)
    fragment_one = bytes([44, 0, 0, 0]) + bytes(4)
    fragment_two = bytes([17, 0, 0, 0]) + bytes(4)
    udp = struct.pack("!HHHH", 5353, 53, 8, 0)
    packet = _ipv6_packet(
        0,
        hop_one + hop_two + fragment_one + fragment_two + udp,
    )

    location = locate_ipv6_transport(packet, ipv6_offset=0, next_header=0)

    assert location.complete is True
    assert location.findings == (
        "duplicate_hop_by_hop",
        "hop_by_hop_not_first",
        "duplicate_fragment",
    )


def test_reports_opaque_and_terminal_chains_without_claiming_transport():
    esp = locate_ipv6_transport(
        _ipv6_packet(50, b"opaque"),
        ipv6_offset=0,
        next_header=50,
    )
    no_next = locate_ipv6_transport(
        _ipv6_packet(59, b""),
        ipv6_offset=0,
        next_header=59,
    )

    assert esp.complete is False
    assert esp.findings == ("opaque_esp",)
    assert no_next.complete is False
    assert no_next.findings == ("no_next_header",)


def test_invalid_bounds_and_short_base_header_are_rejected():
    with pytest.raises(ValueError, match="complete IPv6 base header"):
        locate_ipv6_transport(b"short", ipv6_offset=0, next_header=6)
    with pytest.raises(ValueError, match="max_extension_headers"):
        locate_ipv6_transport(
            _ipv6_packet(6, b""),
            ipv6_offset=0,
            next_header=6,
            max_extension_headers=33,
        )
    with pytest.raises(ValueError, match="max_extension_bytes"):
        locate_ipv6_transport(
            _ipv6_packet(6, b""),
            ipv6_offset=0,
            next_header=6,
            max_extension_bytes=4097,
        )
