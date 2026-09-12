from __future__ import annotations

import ipaddress
import math
import secrets
import socket
import time
from collections.abc import Callable, Iterable
from typing import Any

from security import validate_target_ip

_UDP_TIMEOUT_DEFAULT = 0.35
_UDP_TIMEOUT_MIN = 0.05
_UDP_TIMEOUT_MAX = 1.0
_UDP_RECV_BYTES = 512
# Standard QUERY with one root-name NS/IN question. The question section is:
# QNAME=root (zero-length label), QTYPE=NS (2), QCLASS=IN (1).
_DNS_QUESTION = b"\x00\x00\x02\x00\x01"
_DNS_QUERY_SUFFIX = b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + _DNS_QUESTION
_NTP_UNIX_EPOCH_OFFSET = 2_208_988_800

_ServiceProfile = tuple[int, str]
_SERVICE_PROFILES: dict[str, _ServiceProfile] = {
    "dns": (53, "DNS"),
    "ntp": (123, "NTP"),
}


def _socket_target(target: str, port: int) -> tuple[int, tuple[Any, ...]]:
    host, separator, scope = target.partition("%")
    address = ipaddress.ip_address(host)
    if isinstance(address, ipaddress.IPv6Address):
        scope_id = 0
        if separator:
            scope_id = int(scope) if scope.isdigit() else socket.if_nametoindex(scope)
        return socket.AF_INET6, (host, port, 0, scope_id)
    return socket.AF_INET, (host, port)


def _ntp_transmit_timestamp() -> bytes:
    seconds = int(time.time()) + _NTP_UNIX_EPOCH_OFFSET
    return (seconds & 0xFFFFFFFF).to_bytes(4, "big") + secrets.token_bytes(4)


def _build_probe(profile_name: str) -> tuple[bytes, bytes]:
    if profile_name == "dns":
        correlation = secrets.token_bytes(2)
        return correlation + _DNS_QUERY_SUFFIX, correlation

    correlation = _ntp_transmit_timestamp()
    payload = bytearray(48)
    payload[0] = 0x23  # LI=0, VN=4, mode=3 client
    payload[40:48] = correlation
    return bytes(payload), correlation


def _base_row(port: int, service: str) -> dict[str, object]:
    return {
        "Port": port,
        "Protocol": "UDP",
        "Service": service,
        "Status": "Open|Filtered",
        "Response Time (ms)": "-",
        "Service Detection": "No UDP response",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Low",
        "DNS RCODE": "",
        "DNS Authoritative": "",
        "DNS Recursion Available": "",
        "DNS Truncated": "",
        "NTP Stratum": "",
        "NTP Leap Indicator": "",
        "NTP Kiss Code": "",
    }


def _classify_dns_response(
    payload: bytes, correlation: bytes
) -> tuple[bool, str, dict[str, object]]:
    if len(payload) < 17 or payload[:2] != correlation:
        return False, "", {}
    flags = int.from_bytes(payload[2:4], "big")
    opcode = (flags >> 11) & 0x0F
    if not flags & 0x8000 or opcode != 0:
        return False, "", {}
    if payload[4:6] != b"\x00\x01" or payload[12:17] != _DNS_QUESTION:
        return False, "", {}
    return (
        True,
        "",
        {
            "DNS RCODE": flags & 0x000F,
            "DNS Authoritative": bool(flags & 0x0400),
            "DNS Recursion Available": bool(flags & 0x0080),
            "DNS Truncated": bool(flags & 0x0200),
        },
    )


def _ntp_kiss_code(payload: bytes) -> str:
    if payload[1] != 0:
        return ""
    raw_code = payload[12:16].rstrip(b"\x00")
    if not raw_code or any(byte < 0x20 or byte > 0x7E for byte in raw_code):
        return ""
    return raw_code.decode("ascii")


def _classify_ntp_response(
    payload: bytes, correlation: bytes
) -> tuple[bool, str, dict[str, object]]:
    if len(payload) < 48 or payload[24:32] != correlation:
        return False, "", {}
    first = payload[0]
    leap = (first >> 6) & 0x03
    version = (first >> 3) & 0x07
    mode = first & 0x07
    if version not in {3, 4} or mode != 4:
        return False, "", {}
    return (
        True,
        f"v{version}",
        {
            "NTP Stratum": payload[1],
            "NTP Leap Indicator": leap,
            "NTP Kiss Code": _ntp_kiss_code(payload),
        },
    )


def _probe_one(
    target: str,
    profile_name: str,
    timeout: float,
    socket_factory: Callable[..., Any],
) -> dict[str, object]:
    port, service = _SERVICE_PROFILES[profile_name]
    payload, correlation = _build_probe(profile_name)
    row = _base_row(port, service)
    family, socket_address = _socket_target(target, port)
    started = time.perf_counter()

    try:
        with socket_factory(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(socket_address)
            sock.send(payload)
            response = sock.recv(_UDP_RECV_BYTES)
    except ConnectionRefusedError:
        row["Status"] = "Closed"
        row["Service Detection"] = "ICMP/OS refusal"
        row["Response Time (ms)"] = round((time.perf_counter() - started) * 1000, 2)
        return row
    except (socket.timeout, TimeoutError):
        row["Response Time (ms)"] = round((time.perf_counter() - started) * 1000, 2)
        return row
    except OSError:
        row["Service Detection"] = "UDP probe error"
        row["Response Time (ms)"] = round((time.perf_counter() - started) * 1000, 2)
        return row

    row["Response Time (ms)"] = round((time.perf_counter() - started) * 1000, 2)
    if profile_name == "dns":
        valid, version, metadata = _classify_dns_response(response, correlation)
    else:
        valid, version, metadata = _classify_ntp_response(response, correlation)

    if not valid:
        row["Status"] = "Open"
        row["Service Detection"] = "Unexpected UDP response"
        return row

    row["Status"] = "Open"
    row["Service Detection"] = f"{service} response"
    row["Service Product"] = service
    row["Service Version"] = version
    row["Service Confidence"] = "High"
    row.update(metadata)
    if service == "NTP" and row["NTP Kiss Code"]:
        row["Service Detection"] = "NTP Kiss-o'-Death response"
    return row


def scan_udp_services(
    ip: str,
    *,
    services: Iterable[str] = ("dns", "ntp"),
    timeout: float = _UDP_TIMEOUT_DEFAULT,
    socket_factory: Callable[..., Any] = socket.socket,
) -> list[dict[str, object]]:
    """Run tightly bounded UDP service checks against one authorized local target.

    Only DNS and NTP are supported. Each selected profile sends exactly one small
    datagram, performs no retry, receives at most 512 bytes, and treats silence as
    ``Open|Filtered`` rather than claiming the service is closed. Valid responses
    must correlate to the exact request and expose only bounded protocol-header
    metadata; response payloads and correlation tokens are not retained.
    """
    if not math.isfinite(timeout) or not _UDP_TIMEOUT_MIN <= timeout <= _UDP_TIMEOUT_MAX:
        raise ValueError("UDP timeout must be between 0.05 and 1.0 seconds.")

    selected = tuple(str(item).strip().lower() for item in services)
    unknown = sorted(set(selected) - set(_SERVICE_PROFILES))
    if unknown:
        raise ValueError(f"Unsupported UDP service profile: {unknown[0]}")
    if len(selected) != len(set(selected)):
        raise ValueError("UDP service profiles must be unique.")
    if len(selected) > len(_SERVICE_PROFILES):
        raise ValueError("At most two UDP service profiles may be checked per call.")

    validation = validate_target_ip(ip)
    if not validation.ok:
        return [
            {
                "Port": "-",
                "Protocol": "UDP",
                "Service": "Validation",
                "Status": "Blocked",
                "Response Time (ms)": "-",
                "Service Detection": "Target validation",
                "Service Product": "",
                "Service Version": "",
                "Service Confidence": "Low",
                "DNS RCODE": "",
                "DNS Authoritative": "",
                "DNS Recursion Available": "",
                "DNS Truncated": "",
                "NTP Stratum": "",
                "NTP Leap Indicator": "",
                "NTP Kiss Code": "",
            }
        ]

    target = validation.value or ip.strip()
    return [_probe_one(target, profile, timeout, socket_factory) for profile in selected]
