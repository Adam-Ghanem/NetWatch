from __future__ import annotations

import ipaddress
import struct

from traffic_capture import CaptureFilter, packet_matches, parse_ethernet_frame


def _ethernet_ipv6(payload: bytes, *, next_header: int) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb86dd")
    source = ipaddress.IPv6Address("fd00::10").packed
    destination = ipaddress.IPv6Address("fd00::20").packed
    ipv6 = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(payload),
        next_header,
        64,
        source,
        destination,
    )
    return ethernet + ipv6 + payload


def _tcp_header(source_port: int = 42424, destination_port: int = 443) -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        0,
        0,
        5 << 4,
        0x12,
        65535,
        0,
        0,
    )


def test_ipv6_hop_by_hop_header_reaches_tcp_metadata():
    hop_by_hop = bytes([6, 0]) + bytes(6)
    record = parse_ethernet_frame(
        _ethernet_ipv6(hop_by_hop + _tcp_header(), next_header=0),
        1,
    )

    assert record is not None
    assert record["protocol"] == "TCP"
    assert record["source_port"] == 42424
    assert record["destination_port"] == 443
    assert record["tcp_flags"] == "ACK,SYN"
    assert record["ipv6_extension_headers"] == ["hop_by_hop"]
    assert record["ipv6_fragmented"] is False
    assert record["ipv6_transport_complete"] is True
    assert packet_matches(record, CaptureFilter(protocol="tcp", port=443)) is True


def test_ipv6_first_fragment_can_expose_transport_header():
    fragment_header = bytes([17, 0, 0, 1, 0, 0, 0, 1])
    udp = struct.pack("!HHHH", 5353, 9999, 8, 0)
    record = parse_ethernet_frame(
        _ethernet_ipv6(fragment_header + udp, next_header=44),
        2,
    )

    assert record is not None
    assert record["protocol"] == "UDP"
    assert record["source_port"] == 5353
    assert record["destination_port"] == 9999
    assert record["ipv6_extension_headers"] == ["fragment"]
    assert record["ipv6_fragmented"] is True
    assert record["ipv6_first_fragment"] is True


def test_ipv6_non_initial_fragment_does_not_invent_transport_ports():
    fragment_field = 1 << 3
    fragment_header = bytes([6, 0]) + fragment_field.to_bytes(2, "big") + bytes(4)
    record = parse_ethernet_frame(
        _ethernet_ipv6(fragment_header + bytes(24), next_header=44),
        3,
    )

    assert record is not None
    assert record["protocol"] == "IPv6"
    assert record["source_port"] is None
    assert record["destination_port"] is None
    assert record["ipv6_extension_headers"] == ["fragment"]
    assert record["ipv6_fragmented"] is True
    assert record["ipv6_first_fragment"] is False
    assert record["ipv6_transport_complete"] is True
    assert packet_matches(record, CaptureFilter(protocol="tcp")) is False


def test_truncated_ipv6_extension_chain_fails_closed():
    truncated_hop_by_hop = bytes([6, 1]) + bytes(6)
    record = parse_ethernet_frame(
        _ethernet_ipv6(truncated_hop_by_hop, next_header=0),
        4,
    )

    assert record is not None
    assert record["protocol"] == "IPv6"
    assert record["source_port"] is None
    assert record["destination_port"] is None
    assert record["ipv6_extension_headers"] == ["hop_by_hop"]
    assert record["ipv6_transport_complete"] is False
