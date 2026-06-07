"""Validation and safety helpers for NetWatch."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from config import HIGH_RISK_PORTS, MAX_HOSTS_PER_SCAN, MEDIUM_RISK_PORTS


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    value: str | None = None
    error: str | None = None


def _is_allowed_ip(ip: ipaddress._BaseAddress) -> bool:
    """Allow private, loopback, and link-local lab targets only."""
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def validate_target_ip(target: str) -> ValidationResult:
    """Validate that a target is an allowed lab/local IP address."""
    try:
        ip = ipaddress.ip_address(target.strip())
    except ValueError:
        return ValidationResult(False, error="Use a valid IP address, for example 192.168.1.1")

    if not _is_allowed_ip(ip):
        return ValidationResult(
            False,
            error="For safety, NetWatch only scans private/local IP addresses you control.",
        )

    return ValidationResult(True, value=str(ip))


def _usable_host_count(network: ipaddress._BaseNetwork) -> int:
    """Return an approximate usable-host count without iterating over every IP."""
    if network.version == 4 and network.prefixlen <= 30:
        return max(network.num_addresses - 2, 0)
    return network.num_addresses


def validate_cidr(cidr: str) -> ValidationResult:
    """Validate CIDR and enforce a conservative maximum scan size."""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return ValidationResult(False, error="Invalid CIDR. Example: 192.168.1.0/24")

    if not _is_allowed_ip(network.network_address):
        return ValidationResult(False, error="Only private/local networks are allowed.")

    host_count = _usable_host_count(network)
    if host_count > MAX_HOSTS_PER_SCAN:
        return ValidationResult(
            False,
            error=f"Network too large. Maximum allowed hosts: {MAX_HOSTS_PER_SCAN}.",
        )

    return ValidationResult(True, value=str(network))


def classify_port_risk(port: int, is_open: bool) -> str:
    if not is_open:
        return "None"
    if port in HIGH_RISK_PORTS:
        return "High"
    if port in MEDIUM_RISK_PORTS:
        return "Medium"
    return "Low"


def recommendation_for_port(port: int, is_open: bool) -> str:
    if not is_open:
        return "No action required."

    advice = {
        21: "Avoid FTP when possible; prefer SFTP/SSH and disable anonymous login.",
        22: "Keep SSH patched, disable password login if possible, and use strong keys.",
        23: "Telnet is insecure. Disable it and use SSH instead.",
        25: "Restrict SMTP relay and verify mail-server configuration.",
        53: "Restrict DNS recursion to trusted clients only.",
        80: "Redirect HTTP to HTTPS and keep the web server updated.",
        110: "Avoid plain POP3; use encrypted mail access where possible.",
        143: "Avoid plain IMAP; use encrypted mail access where possible.",
        443: "Verify TLS certificates and keep the web server updated.",
        445: "Expose SMB only inside trusted LANs and keep systems patched.",
        3306: "Do not expose MySQL broadly; bind to localhost/private admin networks.",
        3389: "Restrict RDP with VPN/firewall rules and use strong authentication.",
        5432: "Do not expose PostgreSQL broadly; restrict with firewall and strong auth.",
        8080: "Check admin panels and protect them with authentication/firewall rules.",
    }
    return advice.get(port, "Verify that this service is expected and properly secured.")
