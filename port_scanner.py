from __future__ import annotations

import socket
from typing import List

from config import COMMON_PORTS, DEFAULT_TIMEOUT
from security import classify_port_risk, recommendation_for_port, validate_target_ip


def scan_ports(ip: str, timeout: float = DEFAULT_TIMEOUT) -> List[dict]:
    """Scan a conservative list of common TCP ports on an authorized local target."""
    validation = validate_target_ip(ip)
    if not validation.ok:
        return [{
            "Port": "-",
            "Service": "Validation",
            "Status": "Blocked",
            "Risk": "None",
            "Recommendation": validation.error or "Invalid target",
        }]

    target = validation.value or ip.strip()
    results: List[dict] = []

    for port, service in COMMON_PORTS.items():
        is_open = False
        status = "Closed"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                is_open = sock.connect_ex((target, port)) == 0
                status = "Open" if is_open else "Closed"
            except socket.timeout:
                status = "Filtered/Timeout"
            except OSError:
                status = "Filtered/Unknown"

        results.append({
            "Port": port,
            "Service": service,
            "Status": status,
            "Risk": classify_port_risk(port, is_open),
            "Recommendation": recommendation_for_port(port, is_open),
        })

    return results
