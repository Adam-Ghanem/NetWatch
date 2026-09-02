import socket
import struct
from datetime import datetime, timezone

import pytest
from pcap_import import import_pcap_metadata


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


def _pcap(*frames: bytes, linktype: int = 1) -> bytes:
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, linktype)
    chunks = [global_header]
    for index, frame in enumerate(frames):
        chunks.append(struct.pack("<IIII", 1_788_304_800 + index, 250_000, len(frame), len(frame)))
        chunks.append(frame)
    return b"".join(chunks)


def test_imports_ethernet_pcap_as_metadata_only_capture_summary():
    result = import_pcap_metadata(_pcap(_tcp_frame()), max_packets=100)

    assert result["source"] == "pcap"
    assert result["pcap_version"] == "2.4"
    assert result["linktype"] == 1
    assert result["captured_packets"] == 1
    assert result["payload_retained"] is False
    assert result["packets"][0]["protocol"] == "TCP"
    assert result["packets"][0]["destination_port"] == 443
    assert result["flow_count"] == 1
    assert "payload" not in result["packets"][0]
    assert "raw" not in result["packets"][0]


def test_preserves_packet_timestamp_without_retaining_frame_bytes():
    result = import_pcap_metadata(_pcap(_tcp_frame()), max_packets=10)
    captured_at = datetime.fromisoformat(result["packets"][0]["captured_at"])

    assert captured_at == datetime.fromtimestamp(1_788_304_800.25, tz=timezone.utc)
    assert _tcp_frame().hex() not in str(result)


def test_rejects_unsupported_linktype_and_truncated_records():
    with pytest.raises(ValueError, match="Ethernet"):
        import_pcap_metadata(_pcap(_tcp_frame(), linktype=101))

    truncated = _pcap(_tcp_frame())[:-1]
    with pytest.raises(ValueError, match="truncated"):
        import_pcap_metadata(truncated)


def test_import_limits_and_input_size_fail_closed():
    with pytest.raises(ValueError, match="between 1 and 5000"):
        import_pcap_metadata(_pcap(_tcp_frame()), max_packets=0)
    with pytest.raises(ValueError, match="too large"):
        import_pcap_metadata(bytes(32 * 1024 * 1024 + 1))


def test_import_stops_at_requested_packet_limit():
    result = import_pcap_metadata(_pcap(_tcp_frame(), _tcp_frame()), max_packets=1)

    assert result["captured_packets"] == 1
    assert result["truncated_by_limit"] is True
