from __future__ import annotations

import re
import socket
from dataclasses import dataclass

from ping_checker import ping_host_raw
from security import validate_target_ip


@dataclass(frozen=True)
class HostProfile:
    ip_address: str
    hostname: str
    online: bool
    latency_ms: float | None
    ttl: int | None
    os_hint: str
    notes: str


def parse_latency_ms(output: str) -> float | None:
    patterns = [
        r"time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms",
        r"Average = ([0-9]+)ms",
        r"avg[/=]([0-9]+(?:\.[0-9]+)?)",
    ]
    for pattern in patterns:
        match = re.search(pattern, output, flags=re.IGNORECASE)
        if match:
            return float(match.group(1))
    return None


def parse_ttl(output: str) -> int | None:
    match = re.search(r"ttl[= ]([0-9]+)", output, flags=re.IGNORECASE)
    if match:
        return int(match.group(1))
    return None


def os_hint_from_ttl(ttl: int | None) -> str:
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix or network device"
    if ttl <= 128:
        return "Windows-like host"
    return "Network device or unknown"


def reverse_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except OSError:
        return "-"


def profile_host(ip: str) -> HostProfile:
    validation = validate_target_ip(ip)
    if not validation.ok:
        return HostProfile(
            ip, "-", False, None, None, "Blocked", validation.error or "Invalid target"
        )

    target = validation.value or ip.strip()
    result = ping_host_raw(target)
    output = f"{result.stdout}\n{result.stderr}"
    latency = parse_latency_ms(output)
    ttl = parse_ttl(output)
    online = result.returncode == 0
    hostname = reverse_hostname(target) if online else "-"

    if online:
        notes = "Host replied to ICMP ping"
    else:
        notes = "No ping reply; host may be offline or blocking ICMP"

    return HostProfile(
        ip_address=target,
        hostname=hostname,
        online=online,
        latency_ms=latency,
        ttl=ttl,
        os_hint=os_hint_from_ttl(ttl),
        notes=notes,
    )
