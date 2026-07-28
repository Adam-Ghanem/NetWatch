import ipaddress
import struct

import pytest

from packet_analyzer import CaptureFormatError, analyze_capture


def _ethernet_ipv4_tcp(payload: bytes = b"") -> bytes:
    source_ip = ipaddress.IPv4Address("192.168.1.10").packed
    destination_ip = ipaddress.IPv4Address("192.168.1.20").packed
    tcp = struct.pack(
        "!HHIIBBHHH",
        51515,
        443,
        1,
        0,
        5 << 4,
        0x02,
        64240,
        0,
        0,
    )
    total_length = 20 + len(tcp) + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0x4000,
        64,
        6,
        0,
        source_ip,
        destination_ip,
    )
    ethernet = bytes.fromhex("00112233445566778899AABB0800")
    return ethernet + ipv4 + tcp + payload


def _dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00\x00\x01\x00\x01"


def _ethernet_ipv4_udp_dns(name: str) -> bytes:
    dns = _dns_query(name)
    udp = struct.pack("!HHHH", 53530, 53, 8 + len(dns), 0) + dns
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        2,
        0x4000,
        64,
        17,
        0,
        ipaddress.IPv4Address("192.168.1.10").packed,
        ipaddress.IPv4Address("192.168.1.1").packed,
    )
    return bytes.fromhex("00112233445566778899AABB0800") + ipv4 + udp


def _pcap(*frames: bytes) -> bytes:
    output = bytearray(b"\xd4\xc3\xb2\xa1")
    output.extend(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames, start=1):
        output.extend(struct.pack("<IIII", 1_700_000_000 + index, index, len(frame), len(frame)))
        output.extend(frame)
    return bytes(output)


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    padded_body = body + (b"\x00" * ((-len(body)) % 4))
    length = 12 + len(padded_body)
    return struct.pack("<II", block_type, length) + padded_body + struct.pack("<I", length)


def _pcapng(frame: bytes) -> bytes:
    section = _pcapng_block(
        0x0A0D0D0A,
        b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1),
    )
    interface = _pcapng_block(1, struct.pack("<HHIHH", 1, 0, 65535, 0, 0))
    packet = _pcapng_block(
        6,
        struct.pack("<IIIII", 0, 0, 1_000_000, len(frame), len(frame)) + frame,
    )
    return section + interface + packet


def _analyze(
    data: bytes,
    *,
    maximum_bytes: int = 1024 * 1024,
    maximum_packets: int = 100,
    maximum_rows: int = 100,
    include_dns_names: bool = False,
):
    return analyze_capture(
        data,
        maximum_bytes=maximum_bytes,
        maximum_packets=maximum_packets,
        maximum_rows=maximum_rows,
        include_dns_names=include_dns_names,
    )


def test_pcap_returns_metadata_and_never_returns_payload_bytes():
    secret = b"password=must-not-appear"
    result = _analyze(
        _pcap(
            _ethernet_ipv4_tcp(secret),
            _ethernet_ipv4_udp_dns("private-device.example"),
        )
    )

    assert result["format"] == "pcap"
    assert result["packets_analyzed"] == 2
    assert result["payload_retained"] is False
    assert {row["protocol"] for row in result["protocols"]} == {"TCP", "UDP"}
    assert result["packets"][0]["service"] == "HTTPS"
    assert result["packets"][0]["source_mac"] == "66:77:88:99:AA:BB"
    assert result["packets"][0]["destination_mac"] == "00:11:22:33:44:55"
    assert "must-not-appear" not in str(result)
    assert "private-device.example" not in str(result)
    assert "name hidden" in result["packets"][1]["info"]


def test_dns_name_metadata_requires_explicit_opt_in():
    result = _analyze(
        _pcap(_ethernet_ipv4_udp_dns("printer.office.local")),
        include_dns_names=True,
    )

    assert result["dns_names_included"] is True
    assert "printer.office.local" in result["packets"][0]["info"]


def test_pcapng_enhanced_packet_is_supported():
    result = _analyze(_pcapng(_ethernet_ipv4_tcp()))

    assert result["format"] == "pcapng"
    assert result["link_types"] == ["Ethernet"]
    assert result["packets"][0]["source"] == "192.168.1.10"
    assert result["packets"][0]["destination"] == "192.168.1.20"


def test_packet_rows_are_bounded_while_summary_uses_analyzed_packets():
    frame = _ethernet_ipv4_tcp()
    result = _analyze(
        _pcap(frame, frame, frame),
        maximum_rows=1,
    )

    assert result["packets_analyzed"] == 3
    assert result["packets_returned"] == 1
    assert result["protocols"][0]["packets"] == 3
    assert result["truncated"] is True


def test_capture_packet_processing_limit_is_enforced():
    frame = _ethernet_ipv4_tcp()
    result = _analyze(
        _pcap(frame, frame, frame),
        maximum_packets=2,
        maximum_rows=2,
    )

    assert result["packets_analyzed"] == 2
    assert result["truncated"] is True


@pytest.mark.parametrize(
    "capture",
    [
        b"",
        b"not a capture",
        _pcap(_ethernet_ipv4_tcp())[:-1],
        _pcapng(_ethernet_ipv4_tcp())[:-4],
    ],
)
def test_empty_unknown_and_truncated_captures_are_rejected(capture):
    with pytest.raises(CaptureFormatError):
        _analyze(capture)


def test_capture_byte_limit_is_enforced_in_analyzer_boundary():
    capture = _pcap(_ethernet_ipv4_tcp())

    with pytest.raises(CaptureFormatError):
        _analyze(capture, maximum_bytes=len(capture) - 1)
