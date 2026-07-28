from __future__ import annotations

import re
from dataclasses import dataclass

from device_identity import discover_device_identity
from device_identity import reverse_hostname as resolve_hostname
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
    device_name: str
    device_type: str
    manufacturer: str
    device_model: str
    identity_confidence: str
    identity_evidence: str
    mac_address: str
    mac_address_type: str
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
    return resolve_hostname(ip) or "-"


def profile_host(ip: str) -> HostProfile:
    validation = validate_target_ip(ip)
    if not validation.ok:
        return HostProfile(
            ip_address=ip,
            hostname="-",
            online=False,
            latency_ms=None,
            ttl=None,
            os_hint="Blocked",
            device_name="Unresolved",
            device_type="Unclassified device",
            manufacturer="Unknown",
            device_model="Model unavailable",
            identity_confidence="Low",
            identity_evidence="Target validation failed.",
            mac_address="-",
            mac_address_type="Unavailable",
            notes=validation.error or "Invalid target",
        )

    target = validation.value or ip.strip()
    result = ping_host_raw(target)
    output = f"{result.stdout}\n{result.stderr}"
    latency = parse_latency_ms(output)
    ttl = parse_ttl(output)
    online = result.returncode == 0
    hostname = reverse_hostname(target) if online else "-"
    identity = discover_device_identity(target, ttl=ttl, hostname=hostname) if online else None

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
        os_hint=identity.operating_system if identity else os_hint_from_ttl(ttl),
        device_name=identity.device_name if identity else "Unresolved",
        device_type=identity.device_type if identity else "Unclassified device",
        manufacturer=identity.manufacturer if identity else "Unknown",
        device_model=identity.device_model if identity else "Model unavailable",
        identity_confidence=identity.confidence if identity else "Low",
        identity_evidence=identity.evidence if identity else "No reply; identity was not probed.",
        mac_address=identity.mac_address if identity and identity.mac_address else "-",
        mac_address_type=identity.mac_address_type if identity else "Unavailable",
        notes=notes,
    )
