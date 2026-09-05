import socket
import struct
from datetime import datetime, timezone

from traffic_capture import CaptureFilter, parse_ethernet_frame, summarize_capture


def _ipv4_frame(*, protocol: int, source: str, destination: str, payload: bytes) -> bytes:
    destination_mac = bytes.fromhex("286C07000001")
    source_mac = bytes.fromhex("001CB3000001")
    ethernet = destination_mac + source_mac + struct.pack("!H", 0x0800)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        1,
        0,
        64,
        protocol,
        0,
        socket.inet_aton(source),
        socket.inet_aton(destination),
    )
    return ethernet + ipv4 + payload


def _udp_frame(*, source_port: int, destination_port: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    return _ipv4_frame(
        protocol=17,
        source="192.168.1.10",
        destination="192.168.1.53",
        payload=udp,
    )


def _tcp_frame(*, destination_port: int, payload: bytes) -> bytes:
    tcp = struct.pack(
        "!HHLLBBHHH",
        51_515,
        destination_port,
        0,
        0,
        0x50,
        0x18,
        65_535,
        0,
        0,
    ) + payload
    return _ipv4_frame(
        protocol=6,
        source="192.168.1.10",
        destination="192.168.1.20",
        payload=tcp,
    )


def _dns_query() -> bytes:
    query = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + query


def _tls_client_hello() -> bytes:
    server_name = b"secure.example"
    sni_name = b"\x00" + struct.pack("!H", len(server_name)) + server_name
    sni = struct.pack("!HHH", 0, len(sni_name) + 2, len(sni_name)) + sni_name
    alpn_value = b"h2"
    alpn_list = bytes([len(alpn_value)]) + alpn_value
    alpn = struct.pack("!HHH", 16, len(alpn_list) + 2, len(alpn_list)) + alpn_list
    extensions = sni + alpn
    body = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _record(frame: bytes, sequence: int = 1):
    return parse_ethernet_frame(
        frame,
        sequence,
        captured_at=datetime(2026, 9, 5, tzinfo=timezone.utc),
    )


def _summary(record):
    assert record is not None
    return summarize_capture(
        [record],
        interface="eth0",
        duration_seconds=1,
        capture_filter=CaptureFilter(),
    )


def test_dns_query_metadata_is_correlated_without_payload_retention():
    record = _record(_udp_frame(source_port=53_000, destination_port=53, payload=_dns_query()))
    summary = _summary(record)

    flow = summary["flows"][0]
    assert flow["protocol_event_count"] == 1
    assert flow["protocol_events"] == [
        {
            "event_type": "dns",
            "timestamp": "2026-09-05T00:00:00.000+00:00",
            "metadata": {"query": "example.com", "qtype": "A", "rcode": 0},
        }
    ]
    assert "_protocol_event" not in summary["packets"][0]
    assert summary["payload_retained"] is False


def test_http_metadata_keeps_host_and_method_but_drops_sensitive_headers_and_uri():
    request = (
        b"GET /private?token=secret HTTP/1.1\r\n"
        b"Host: portal.example\r\n"
        b"Authorization: Bearer very-secret\r\n"
        b"Cookie: session=very-secret\r\n\r\n"
        b"body-must-not-be-retained"
    )
    summary = _summary(_record(_tcp_frame(destination_port=80, payload=request)))

    event = summary["flows"][0]["protocol_events"][0]
    assert event["event_type"] == "http"
    assert event["metadata"] == {"host": "portal.example", "method": "GET"}
    serialized = repr(summary).lower()
    assert "/private" not in serialized
    assert "very-secret" not in serialized
    assert "body-must-not-be-retained" not in serialized
    assert "authorization" not in serialized
    assert "cookie" not in serialized


def test_tls_client_hello_metadata_is_correlated_without_certificate_or_payload_data():
    summary = _summary(_record(_tcp_frame(destination_port=443, payload=_tls_client_hello())))

    event = summary["flows"][0]["protocol_events"][0]
    assert event["event_type"] == "tls"
    assert event["metadata"] == {
        "alpn": "h2",
        "server_name": "secure.example",
        "version": "TLS 1.2",
    }
    assert "payload" not in repr(event).lower()
    assert "certificate" not in repr(event).lower()


def test_incomplete_or_unrecognized_application_data_does_not_create_protocol_events():
    record = _record(_tcp_frame(destination_port=443, payload=b"not-a-complete-protocol-record"))
    summary = _summary(record)

    flow = summary["flows"][0]
    assert "protocol_events" not in flow
    assert "protocol_event_count" not in flow
    assert "_protocol_event" not in summary["packets"][0]
