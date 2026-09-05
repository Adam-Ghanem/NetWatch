from __future__ import annotations

import struct
from typing import Any

_MAX_INSPECTION_BYTES = 8_192
_MAX_TEXT_LENGTH = 512
_HTTP_METHODS = {
    "CONNECT",
    "DELETE",
    "GET",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
    "TRACE",
}
_DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}
_TLS_VERSIONS = {
    (3, 1): "TLS 1.0",
    (3, 2): "TLS 1.1",
    (3, 3): "TLS 1.2",
    (3, 4): "TLS 1.3",
}


def _text(value: bytes) -> str:
    return value.decode("ascii", errors="replace").strip()[:_MAX_TEXT_LENGTH]


def _tcp_payload(frame: bytes, offset: int) -> bytes:
    if offset < 0 or len(frame) < offset + 20:
        return b""
    header_length = (frame[offset + 12] >> 4) * 4
    if header_length < 20 or len(frame) < offset + header_length:
        return b""
    return frame[offset + header_length : offset + header_length + _MAX_INSPECTION_BYTES]


def _udp_payload(frame: bytes, offset: int) -> bytes:
    if offset < 0 or len(frame) < offset + 8:
        return b""
    return frame[offset + 8 : offset + 8 + _MAX_INSPECTION_BYTES]


def _dns_name(message: bytes, offset: int) -> tuple[str, int] | None:
    labels: list[str] = []
    cursor = offset
    total_length = 0
    for _ in range(128):
        if cursor >= len(message):
            return None
        length = message[cursor]
        cursor += 1
        if length == 0:
            return ".".join(labels)[:253], cursor
        if length & 0xC0:
            return None
        if length > 63 or cursor + length > len(message):
            return None
        label = _text(message[cursor : cursor + length])
        total_length += len(label) + (1 if labels else 0)
        if total_length > 253:
            return None
        labels.append(label)
        cursor += length
    return None


def _dns_event(payload: bytes, *, tcp: bool) -> dict[str, object] | None:
    message = payload
    if tcp:
        if len(payload) < 2:
            return None
        message_length = struct.unpack("!H", payload[:2])[0]
        if message_length < 12 or len(payload) < message_length + 2:
            return None
        message = payload[2 : message_length + 2]
    if len(message) < 12:
        return None
    _identifier, flags, question_count, _answers, _authority, _additional = struct.unpack(
        "!HHHHHH", message[:12]
    )
    if question_count < 1:
        return None
    parsed_name = _dns_name(message, 12)
    if parsed_name is None:
        return None
    query, cursor = parsed_name
    if cursor + 4 > len(message):
        return None
    qtype, _qclass = struct.unpack("!HH", message[cursor : cursor + 4])
    return {
        "event_type": "dns",
        "metadata": {
            "query": query,
            "qtype": _DNS_TYPES.get(qtype, str(qtype)),
            "rcode": flags & 0x000F,
        },
    }


def _http_event(payload: bytes) -> dict[str, object] | None:
    header_end = payload.find(b"\r\n\r\n")
    if header_end < 0:
        return None
    header = payload[:header_end]
    lines = header.split(b"\r\n")
    if not lines:
        return None
    first_line = _text(lines[0])
    metadata: dict[str, object] = {}
    if first_line.startswith("HTTP/"):
        parts = first_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            return None
        metadata["status_code"] = int(parts[1])
    else:
        parts = first_line.split(" ", 2)
        if len(parts) < 3 or parts[0] not in _HTTP_METHODS or not parts[2].startswith("HTTP/"):
            return None
        metadata["method"] = parts[0]

    for raw_line in lines[1:]:
        name, separator, value = raw_line.partition(b":")
        if not separator:
            continue
        normalized = name.strip().lower()
        if normalized == b"host" and "method" in metadata:
            metadata["host"] = _text(value)
        elif normalized == b"content-type" and "status_code" in metadata:
            metadata["content_type"] = _text(value)
    return {"event_type": "http", "metadata": metadata}


def _tls_server_name(data: bytes) -> str:
    if len(data) < 5:
        return ""
    list_length = struct.unpack("!H", data[:2])[0]
    if list_length + 2 > len(data):
        return ""
    cursor = 2
    end = 2 + list_length
    while cursor + 3 <= end:
        name_type = data[cursor]
        name_length = struct.unpack("!H", data[cursor + 1 : cursor + 3])[0]
        cursor += 3
        if cursor + name_length > end:
            return ""
        if name_type == 0:
            return _text(data[cursor : cursor + name_length])
        cursor += name_length
    return ""


def _tls_alpn(data: bytes) -> str:
    if len(data) < 3:
        return ""
    list_length = struct.unpack("!H", data[:2])[0]
    if list_length + 2 > len(data):
        return ""
    protocol_length = data[2]
    if protocol_length < 1 or 3 + protocol_length > len(data):
        return ""
    return _text(data[3 : 3 + protocol_length])


def _tls_event(payload: bytes) -> dict[str, object] | None:
    if len(payload) < 9 or payload[0] != 0x16:
        return None
    record_length = struct.unpack("!H", payload[3:5])[0]
    if record_length < 4 or len(payload) < 5 + record_length:
        return None
    if payload[5] != 0x01:
        return None
    handshake_length = int.from_bytes(payload[6:9], "big")
    if handshake_length < 34 or 9 + handshake_length > 5 + record_length:
        return None
    body = payload[9 : 9 + handshake_length]
    if len(body) < 35:
        return None

    version = _TLS_VERSIONS.get((body[0], body[1]), f"0x{body[0]:02x}{body[1]:02x}")
    cursor = 34
    session_length = body[cursor]
    cursor += 1 + session_length
    if cursor + 2 > len(body):
        return None
    cipher_length = struct.unpack("!H", body[cursor : cursor + 2])[0]
    cursor += 2 + cipher_length
    if cursor >= len(body):
        return None
    compression_length = body[cursor]
    cursor += 1 + compression_length
    if cursor + 2 > len(body):
        return {"event_type": "tls", "metadata": {"version": version}}
    extensions_length = struct.unpack("!H", body[cursor : cursor + 2])[0]
    cursor += 2
    extensions_end = min(len(body), cursor + extensions_length)

    metadata: dict[str, object] = {"version": version}
    while cursor + 4 <= extensions_end:
        extension_type, extension_length = struct.unpack("!HH", body[cursor : cursor + 4])
        cursor += 4
        if cursor + extension_length > extensions_end:
            break
        extension = body[cursor : cursor + extension_length]
        cursor += extension_length
        if extension_type == 0:
            server_name = _tls_server_name(extension)
            if server_name:
                metadata["server_name"] = server_name
        elif extension_type == 16:
            alpn = _tls_alpn(extension)
            if alpn:
                metadata["alpn"] = alpn
    return {"event_type": "tls", "metadata": metadata}


def extract_protocol_event(
    frame: bytes,
    *,
    transport_offset: int | None,
    protocol: str,
    source_port: int | None,
    destination_port: int | None,
) -> dict[str, object] | None:
    """Extract one bounded DNS/TLS/HTTP metadata event without retaining payload bytes.

    This parser is intentionally packet-local: it does not reassemble TCP streams and
    therefore only reports metadata that is complete in the current packet. HTTP URI,
    cookies, authorization headers, bodies and certificate contents are never copied.
    """
    if transport_offset is None:
        return None
    normalized_protocol = protocol.upper()
    if normalized_protocol == "UDP":
        payload = _udp_payload(frame, transport_offset)
        if 53 in {source_port, destination_port}:
            return _dns_event(payload, tcp=False)
        return None
    if normalized_protocol != "TCP":
        return None

    payload = _tcp_payload(frame, transport_offset)
    if not payload:
        return None
    if 53 in {source_port, destination_port}:
        dns = _dns_event(payload, tcp=True)
        if dns is not None:
            return dns
    tls = _tls_event(payload)
    if tls is not None:
        return tls
    return _http_event(payload)
