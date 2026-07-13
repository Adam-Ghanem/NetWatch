from __future__ import annotations

import errno
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


def _scan_one_port(target: str, port: int, service: str, timeout: float) -> dict:
    is_open = False
    status = "Closed/Unknown"
    response_time: float | None = None
    started = time.perf_counter()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((target, port))
            response_time = (time.perf_counter() - started) * 1000
            if code == 0:
                is_open = True
                status = "Open"
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
    }


def scan_ports(ip: str, timeout: float = DEFAULT_TIMEOUT) -> List[dict]:
    """Scan a conservative list of common TCP ports on an authorized local target."""
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
