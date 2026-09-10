from __future__ import annotations

import ipaddress
import math
import socket
import time
from collections.abc import Callable, Iterable
from typing import Any

from security import validate_target_ip

_UDP_TIMEOUT_DEFAULT = 0.35
_UDP_TIMEOUT_MIN = 0.05
_UDP_TIMEOUT_MAX = 1.0
_UDP_RECV_BYTES = 512
_DNS_TXID = b"NW"
_DNS_QUERY = _DNS_TXID + b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01"
_NTP_QUERY = bytes([0x23]) + (b"\x00" * 47)  # LI=0, VN=4, mode=3 client

_ServiceProfile = tuple[int, str, bytes]
_SERVICE_PROFILES: dict[str, _ServiceProfile] = {
    "dns": (53, "DNS", _DNS_QUERY),
    "ntp": (123, "NTP", _NTP_QUERY),
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
    }


def _classify_dns_response(payload: bytes) -> tuple[bool, str]:
    if len(payload) < 12 or payload[:2] != _DNS_TXID:
        return False, ""
    flags = int.from_bytes(payload[2:4], "big")
    return bool(flags & 0x8000), ""


def _classify_ntp_response(payload: bytes) -> tuple[bool, str]:
    if len(payload) < 48:
        return False, ""
    first = payload[0]
    version = (first >> 3) & 0x07
    mode = first & 0x07
    if version not in {3, 4} or mode not in {4, 5}:
        return False, ""
    return True, f"v{version}"


def _probe_one(
    target: str,
    profile_name: str,
    timeout: float,
    socket_factory: Callable[..., Any],
) -> dict[str, object]:
    port, service, payload = _SERVICE_PROFILES[profile_name]
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
        valid, version = _classify_dns_response(response)
    else:
        valid, version = _classify_ntp_response(response)

    if not valid:
        row["Status"] = "Open"
        row["Service Detection"] = "Unexpected UDP response"
        return row

    row["Status"] = "Open"
    row["Service Detection"] = f"{service} response"
    row["Service Product"] = service
    row["Service Version"] = version
    row["Service Confidence"] = "High"
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
    ``Open|Filtered`` rather than claiming the service is closed.
    """
    if not math.isfinite(timeout) or not _UDP_TIMEOUT_MIN <= timeout <= _UDP_TIMEOUT_MAX:
        raise ValueError("UDP timeout must be between 0.05 and 1.0 seconds.")

    selected = tuple(str(item).strip().lower() for item in services)
    unknown = sorted(set(selected) - set(_SERVICE_PROFILES))
    if unknown:
        raise ValueError(f"Unsupported UDP service profile: {unknown[0]}")
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
            }
        ]

    target = validation.value or ip.strip()
    return [_probe_one(target, profile, timeout, socket_factory) for profile in selected]
