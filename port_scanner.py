from __future__ import annotations

import socket
import time
from typing import List

from config import COMMON_PORTS, DEFAULT_TIMEOUT
from security import classify_port_risk, recommendation_for_port, validate_target_ip
from service_catalog import guess_device_role, service_info


def scan_ports(ip: str, timeout: float = DEFAULT_TIMEOUT) -> List[dict]:
    """Scan a conservative list of common TCP ports on an authorized local target."""
    validation = validate_target_ip(ip)
    if not validation.ok:
        return [{
            "Port": "-",
            "Protocol": "TCP",
            "Service": "Validation",
            "Status": "Blocked",
            "Response Time (ms)": "-",
            "Risk": "None",
            "Description": "Target validation failed",
            "Common Role": "-",
            "Recommendation": validation.error or "Invalid target",
        }]

    target = validation.value or ip.strip()
    results: List[dict] = []

    for port, service in COMMON_PORTS.items():
        is_open = False
        status = "Closed"
        response_time: float | None = None
        started = time.perf_counter()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                is_open = sock.connect_ex((target, port)) == 0
                response_time = (time.perf_counter() - started) * 1000
                status = "Open" if is_open else "Closed"
            except socket.timeout:
                status = "Filtered/Timeout"
            except OSError:
                status = "Filtered/Unknown"

        details = service_info(port)
        results.append({
            "Port": port,
            "Protocol": details["protocol"],
            "Service": service,
            "Status": status,
            "Response Time (ms)": round(response_time, 2) if response_time is not None else "-",
            "Risk": classify_port_risk(port, is_open),
            "Description": details["description"],
            "Common Role": details["common_role"],
            "Recommendation": recommendation_for_port(port, is_open),
        })

    open_ports = [int(row["Port"]) for row in results if row["Status"] == "Open" and isinstance(row["Port"], int)]
    role = guess_device_role(open_ports)
    for row in results:
        row["Device Role Hint"] = role

    return results
