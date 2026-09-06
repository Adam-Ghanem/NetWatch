from __future__ import annotations

import errno
import ipaddress
import math
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from config import COMMON_PORTS, DEFAULT_TIMEOUT, PORT_SCAN_WORKERS
from security import classify_port_risk, recommendation_for_port, validate_target_ip
from service_catalog import guess_device_role, service_info

_CLOSED_CODES = {errno.ECONNREFUSED, 10061}
_FILTERED_CODES = {
    errno.ETIMEDOUT,
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    getattr(errno, "EHOSTDOWN", 112),
    10060,
    10065,
    10051,
    10064,
}
_SSH_GREETING_BYTES = 256
_SSH_GREETING_TIMEOUT_SECONDS = 0.25
_FTP_GREETING_BYTES = 256
_FTP_GREETING_TIMEOUT_SECONDS = 0.25
_SMTP_GREETING_BYTES = 256
_SMTP_GREETING_TIMEOUT_SECONDS = 0.25
_ServiceEvidence = dict[str, str]


def _socket_target(target: str, port: int) -> tuple[int, tuple[object, ...]]:
    host, separator, scope = target.partition("%")
    address = ipaddress.ip_address(host)
    if isinstance(address, ipaddress.IPv6Address):
        scope_id = 0
        if separator:
            scope_id = int(scope) if scope.isdigit() else socket.if_nametoindex(scope)
        return socket.AF_INET6, (host, port, 0, scope_id)
    return socket.AF_INET, (host, port)


def _default_service_evidence() -> dict[str, str]:
    return {
        "Service Detection": "Port catalog",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Low",
    }


def _ssh_service_evidence(sock: socket.socket, timeout: float) -> dict[str, str]:
    """Read and parse one bounded SSH identification line without returning raw banner data."""
    try:
        sock.settimeout(min(timeout, _SSH_GREETING_TIMEOUT_SECONDS))
        payload = sock.recv(_SSH_GREETING_BYTES)
    except (OSError, socket.timeout):
        return _default_service_evidence()

    first_line = payload.splitlines()[0] if payload else b""
    greeting = first_line.decode("ascii", errors="ignore").strip()
    if not greeting.startswith("SSH-"):
        return _default_service_evidence()

    parts = greeting.split("-", 2)
    if len(parts) != 3 or not parts[2].strip():
        return _default_service_evidence()

    software_token = parts[2].strip().split()[0][:120]
    product = ""
    version = ""
    confidence = "Medium"
    if software_token.startswith("OpenSSH_"):
        product = "OpenSSH"
        version = software_token.removeprefix("OpenSSH_")[:80]
        confidence = "High" if version else "Medium"
    else:
        product = software_token.replace("_", " ")[:80]

    return {
        "Service Detection": "SSH greeting",
        "Service Product": product,
        "Service Version": version,
        "Service Confidence": confidence,
    }


def _ftp_service_evidence(sock: socket.socket, timeout: float) -> dict[str, str]:
    """Read one bounded FTP server greeting and retain only allowlisted product/version evidence."""
    try:
        sock.settimeout(min(timeout, _FTP_GREETING_TIMEOUT_SECONDS))
        payload = sock.recv(_FTP_GREETING_BYTES)
    except (OSError, socket.timeout):
        return _default_service_evidence()

    first_line = payload.splitlines()[0] if payload else b""
    greeting = first_line.decode("ascii", errors="ignore").strip()
    if not greeting.startswith("220"):
        return _default_service_evidence()

    tokens = greeting.split()
    for index, raw_token in enumerate(tokens):
        token = raw_token.strip("()[]{}<>,;:")
        product = ""
        if token == "ProFTPD":
            product = "ProFTPD"
        elif token.lower() == "vsftpd":
            product = "vsftpd"
        if not product:
            continue

        version = ""
        if index + 1 < len(tokens):
            version = tokens[index + 1].strip("()[]{}<>,;:")[:80]
        return {
            "Service Detection": "FTP greeting",
            "Service Product": product,
            "Service Version": version,
            "Service Confidence": "High" if version else "Medium",
        }

    return {
        "Service Detection": "FTP greeting",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Medium",
    }


def _smtp_service_evidence(sock: socket.socket, timeout: float) -> _ServiceEvidence:
    """Read a bounded SMTP greeting and retain only allowlisted product/version evidence."""
    try:
        sock.settimeout(min(timeout, _SMTP_GREETING_TIMEOUT_SECONDS))
        payload = sock.recv(_SMTP_GREETING_BYTES)
    except (OSError, socket.timeout):
        return _default_service_evidence()

    first_line = payload.splitlines()[0] if payload else b""
    greeting = first_line.decode("ascii", errors="ignore").strip()
    if not greeting.startswith("220"):
        return _default_service_evidence()

    tokens = greeting.split()
    for index, raw_token in enumerate(tokens):
        token = raw_token.strip("()[]{}<>,;:")
        product = ""
        if token == "Postfix":
            product = "Postfix"
        elif token == "Exim":
            product = "Exim"
        if not product:
            continue

        version = ""
        if index + 1 < len(tokens):
            candidate = tokens[index + 1].strip("()[]{}<>,;:")[:80]
            if candidate and candidate[0].isdigit():
                version = candidate
        return {
            "Service Detection": "SMTP greeting",
            "Service Product": product,
            "Service Version": version,
            "Service Confidence": "High" if version else "Medium",
        }

    return {
        "Service Detection": "SMTP greeting",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Medium",
    }


def _scan_one_port(target: str, port: int, service: str, timeout: float) -> dict:
    is_open = False
    status = "Closed/Unknown"
    response_time: float | None = None
    service_evidence = _default_service_evidence()
    started = time.perf_counter()

    try:
        family, socket_address = _socket_target(target, port)
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex(socket_address)
            response_time = (time.perf_counter() - started) * 1000
            if code == 0:
                is_open = True
                status = "Open"
                normalized_service = service.lower()
                if normalized_service == "ssh" or port == 22:
                    service_evidence = _ssh_service_evidence(sock, timeout)
                elif normalized_service == "ftp" or port == 21:
                    service_evidence = _ftp_service_evidence(sock, timeout)
                elif normalized_service in {"smtp", "submission"} or port in {25, 587}:
                    service_evidence = _smtp_service_evidence(sock, timeout)
            elif code in _CLOSED_CODES:
                status = "Closed"
            elif code in _FILTERED_CODES:
                status = "Filtered/Unreachable"
            else:
                status = "Closed/Unknown"
    except socket.timeout:
        status = "Filtered/Timeout"
    except OSError:
        status = "Filtered/Unknown"

    details = service_info(port)
    return {
        "Port": port,
        "Protocol": details["protocol"],
        "Service": service,
        "Status": status,
        "Response Time (ms)": round(response_time, 2) if response_time is not None else "-",
        "Risk": classify_port_risk(port, is_open),
        "Description": details["description"],
        "Common Role": details["common_role"],
        "Recommendation": recommendation_for_port(port, is_open),
        **service_evidence,
    }


def scan_ports(ip: str, timeout: float = DEFAULT_TIMEOUT) -> List[dict]:
    """Scan conservative common TCP ports on an authorized local IPv4/IPv6 target."""
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 10:
        raise ValueError("Timeout must be greater than zero and no more than 10 seconds.")

    validation = validate_target_ip(ip)
    if not validation.ok:
        return [
            {
                "Port": "-",
                "Protocol": "TCP",
                "Service": "Validation",
                "Status": "Blocked",
                "Response Time (ms)": "-",
                "Risk": "None",
                "Description": "Target validation failed",
                "Common Role": "-",
                "Recommendation": validation.error or "Invalid target",
                **_default_service_evidence(),
            }
        ]

    target = validation.value or ip.strip()
    worker_count = max(1, min(PORT_SCAN_WORKERS, len(COMMON_PORTS)))
    results: List[dict] = []

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(_scan_one_port, target, port, service, timeout): port
            for port, service in COMMON_PORTS.items()
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                port = futures[future]
                service = COMMON_PORTS[port]
                details = service_info(port)
                results.append(
                    {
                        "Port": port,
                        "Protocol": details["protocol"],
                        "Service": service,
                        "Status": "Error",
                        "Response Time (ms)": "-",
                        "Risk": "None",
                        "Description": details["description"],
                        "Common Role": details["common_role"],
                        "Recommendation": "The check failed; review the local error log and retry.",
                        **_default_service_evidence(),
                    }
                )

    results.sort(key=lambda row: int(row["Port"]) if isinstance(row["Port"], int) else 0)
    open_ports = [
        int(row["Port"])
        for row in results
        if row["Status"] == "Open" and isinstance(row["Port"], int)
    ]
    role = guess_device_role(open_ports)
    for row in results:
        row["Device Role Hint"] = role

    return results
