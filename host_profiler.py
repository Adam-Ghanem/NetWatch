from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass

from device_identity import identity_for_ip, reverse_hostname
from ping_checker import ping_host_raw
from security import validate_target_ip


@dataclass(frozen=True)
class HostProfile:
    ip_address: str
    address_family: str
    hostname: str
    online: bool
    reachability_status: str
    latency_ms: float | None
    ttl: int | None
    os_hint: str
    notes: str
    mac_address: str
    manufacturer: str
    device_name: str
    device_type: str
    device_family: str
    identity_confidence: str
    identity_source: str
    randomized_mac: bool


def _address_family(value: str) -> str:
    address = value.strip().split("%", 1)[0]
    try:
        version = ipaddress.ip_address(address).version
    except ValueError:
        return "unknown"
    return "ipv6" if version == 6 else "ipv4"


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


def profile_host(ip: str) -> HostProfile:
    validation = validate_target_ip(ip)
    if not validation.ok:
        identity = identity_for_ip(ip)
        return HostProfile(
            ip_address=ip,
            address_family=_address_family(ip),
            hostname="-",
            online=False,
            reachability_status="blocked",
            latency_ms=None,
            ttl=None,
            os_hint="Blocked",
            notes=validation.error or "Invalid target",
            mac_address=identity.mac_address,
            manufacturer=identity.manufacturer,
            device_name=identity.device_name,
            device_type=identity.device_type,
            device_family=identity.device_family,
            identity_confidence=identity.identity_confidence,
            identity_source=identity.identity_source,
            randomized_mac=identity.randomized_mac,
        )

    target = validation.value or ip.strip()
    try:
        result = ping_host_raw(target)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        # A missing executable, denied process launch, timeout, or decode failure
        # means the probe did not produce reachability evidence.
        result = None

    output = f"{result.stdout}\n{result.stderr}" if result is not None else ""
    latency = parse_latency_ms(output)
    ttl = parse_ttl(output)
    online = result is not None and result.returncode == 0
    reachability_status = (
        "online" if online else "offline" if result is not None else "unknown"
    )
    hostname = reverse_hostname(target) if online else "-"
    identity = identity_for_ip(target, hostname=hostname) if online else identity_for_ip(target)

    if online:
        notes = "Host replied to ICMP ping"
    elif result is None:
        notes = "ICMP probe unavailable; reachability is unknown"
    else:
        notes = "No ping reply; host may be offline or blocking ICMP"

    return HostProfile(
        ip_address=target,
        address_family=_address_family(target),
        hostname=hostname,
        online=online,
        reachability_status=reachability_status,
        latency_ms=latency,
        ttl=ttl,
        os_hint=os_hint_from_ttl(ttl),
        notes=notes,
        mac_address=identity.mac_address,
        manufacturer=identity.manufacturer,
        device_name=identity.device_name,
        device_type=identity.device_type,
        device_family=identity.device_family,
        identity_confidence=identity.identity_confidence,
        identity_source=identity.identity_source,
        randomized_mac=identity.randomized_mac,
    )
