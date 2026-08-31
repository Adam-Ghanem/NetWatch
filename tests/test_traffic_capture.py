import socket
import struct
from datetime import datetime, timezone

import pytest

import traffic_capture
from traffic_capture import (
    CaptureFilter,
    CapturePermissionError,
    build_capture_filter,
    capture_traffic,
    packet_matches,
    parse_ethernet_frame,
    resolve_capture_interface,
    summarize_capture,
)


def _tcp_frame() -> bytes:
    destination_mac = bytes.fromhex("286C07000001")
    source_mac = bytes.fromhex("001CB3000001")
    ethernet = destination_mac + source_mac + struct.pack("!H", 0x0800)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        1,
        0,
        64,
        6,
        0,
        socket.inet_aton("192.168.1.10"),
        socket.inet_aton("192.168.1.20"),
    )
    tcp = struct.pack("!HHLLBBHHH", 51_515, 443, 0, 0, 0x50, 0x12, 65_535, 0, 0)
    return ethernet + ipv4 + tcp


def _arp_frame() -> bytes:
    destination_mac = bytes.fromhex("FFFFFFFFFFFF")
    source_mac = bytes.fromhex("286C07000001")
    ethernet = destination_mac + source_mac + struct.pack("!H", 0x0806)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        1,
        0x0800,
        6,
        4,
        1,
        source_mac,
        socket.inet_aton("192.168.1.20"),
        bytes(6),
        socket.inet_aton("192.168.1.1"),
    )
    return ethernet + arp


def _vlan_udp_frame() -> bytes:
    destination_mac = bytes.fromhex("001CB3000001")
    source_mac = bytes.fromhex("286C07000001")
    ethernet = destination_mac + source_mac + struct.pack("!HHH", 0x8100, 100, 0x0800)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        2,
        0,
        64,
        17,
        0,
        socket.inet_aton("192.168.1.20"),
        socket.inet_aton("192.168.1.1"),
    )
    udp = struct.pack("!HHHH", 53_000, 53, 8, 0)
    return ethernet + ipv4 + udp


def test_parser_exposes_headers_without_payload_or_hex_dump():
    record = parse_ethernet_frame(
        _tcp_frame(),
        1,
        captured_at=datetime(2026, 7, 28, tzinfo=timezone.utc),
    )

    assert record is not None
    assert record["protocol"] == "TCP"
    assert record["source_ip"] == "192.168.1.10"
    assert record["destination_ip"] == "192.168.1.20"
    assert record["source_port"] == 51_515
    assert record["destination_port"] == 443
    assert record["tcp_flags"] == "ACK,SYN"
    assert record["source_mac"] == "00:1C:B3:00:00:01"
    assert "payload" not in record
    assert "raw" not in record


def test_arp_and_short_frames_are_handled_safely():
    record = parse_ethernet_frame(_arp_frame(), 1)

    assert record is not None
    assert record["protocol"] == "ARP"
    assert record["source_ip"] == "192.168.1.20"
    assert record["destination_ip"] == "192.168.1.1"
    assert parse_ethernet_frame(b"short", 2) is None


def test_vlan_and_udp_headers_are_reported_without_payload():
    record = parse_ethernet_frame(_vlan_udp_frame(), 1)

    assert record is not None
    assert record["protocol"] == "UDP"
    assert record["vlan_id"] == 100
    assert record["source_port"] == 53_000
    assert record["destination_port"] == 53
    assert "payload" not in record


def test_capture_filters_are_validated_and_applied():
    record = parse_ethernet_frame(_tcp_frame(), 1)
    assert record is not None

    assert packet_matches(record, build_capture_filter(protocol="tcp", port=443))
    assert packet_matches(record, build_capture_filter(ip_address="192.168.1.10"))
    assert not packet_matches(record, build_capture_filter(protocol="udp"))
    assert not packet_matches(record, build_capture_filter(port=53))

    with pytest.raises(ValueError, match="literal"):
        build_capture_filter(ip_address="example.com")
    with pytest.raises(ValueError, match="Port filters"):
        build_capture_filter(protocol="arp", port=53)


def test_capture_summary_includes_protocols_conversations_and_device_hints():
    tcp = parse_ethernet_frame(_tcp_frame(), 1)
    arp = parse_ethernet_frame(_arp_frame(), 2)
    assert tcp is not None and arp is not None

    summary = summarize_capture(
        [tcp, arp],
        interface="eth0",
        duration_seconds=5,
        capture_filter=CaptureFilter(),
    )

    assert summary["captured_packets"] == 2
    assert summary["payload_retained"] is False
    assert summary["protocols"] == [
        {"protocol": "ARP", "packets": 1},
        {"protocol": "TCP", "packets": 1},
    ]
    assert summary["conversations"][0]["bytes"] >= summary["conversations"][1]["bytes"]
    devices = {item["mac_address"]: item for item in summary["devices"]}
    assert devices["00:1C:B3:00:00:01"]["manufacturer"].startswith("Apple")
    assert devices["28:6C:07:00:00:01"]["device_name"] == "Xiaomi / Redmi device"


def test_capture_summary_exposes_canonical_flow_records():
    tcp = parse_ethernet_frame(
        _tcp_frame(),
        1,
        captured_at=datetime(2026, 8, 31, tzinfo=timezone.utc),
    )
    assert tcp is not None

    summary = summarize_capture(
        [tcp],
        interface="eth0",
        duration_seconds=5,
        capture_filter=CaptureFilter(),
    )

    assert summary["flow_count"] == 1
    flow = summary["flows"][0]
    assert flow["protocol"] == "TCP"
    assert flow["service"] == "https"
    assert flow["originator"] == {"ip": "192.168.1.10", "port": 51_515}
    assert flow["responder"] == {"ip": "192.168.1.20", "port": 443}
    assert flow["tcp_state"] == "establishing"
    assert flow["packets"] == 1
    assert flow["bytes"] == len(_tcp_frame())
    assert "payload" not in flow


def test_interface_selection_only_accepts_reported_interfaces(monkeypatch):
    monkeypatch.setattr(
        traffic_capture,
        "capture_interfaces",
        lambda: [
            {"name": "eth0", "ipv4_address": "192.168.1.10", "mac_address": "-", "loopback": False},
            {"name": "lo", "ipv4_address": "127.0.0.1", "mac_address": "-", "loopback": True},
        ],
    )
    monkeypatch.setattr(traffic_capture, "_default_interface", lambda _: "eth0")

    assert resolve_capture_interface("auto") == "eth0"
    assert resolve_capture_interface("lo") == "lo"
    with pytest.raises(ValueError, match="reported"):
        resolve_capture_interface("../../etc/passwd")


def test_capture_socket_is_closed_when_bind_permission_is_denied(monkeypatch):
    class FakeSocket:
        closed = False

        def bind(self, _address):
            raise PermissionError("not permitted")

        def close(self):
            self.closed = True

    handle = FakeSocket()
    monkeypatch.setattr(traffic_capture, "resolve_capture_interface", lambda _: "eth0")
    monkeypatch.setattr(traffic_capture.socket, "socket", lambda *_args: handle)

    with pytest.raises(CapturePermissionError):
        capture_traffic(
            interface="eth0",
            duration_seconds=1,
            max_packets=1,
            capture_filter=CaptureFilter(),
        )

    assert handle.closed is True
