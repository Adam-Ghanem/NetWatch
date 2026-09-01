"""Validation and safety helpers for NetWatch."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from config import HIGH_RISK_PORTS, MAX_HOSTS_PER_SCAN, MEDIUM_RISK_PORTS

ALLOWED_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)
ALLOWED_IPV6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = tuple(
    ipaddress.IPv6Network(cidr) for cidr in ("fc00::/7", "fe80::/10", "::1/128")
)


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    value: str | None = None
    error: str | None = None


def _is_allowed_ipv4(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in network for network in ALLOWED_IPV4_NETWORKS)


def _is_allowed_ipv4_network(network: ipaddress.IPv4Network) -> bool:
    return any(network.subnet_of(allowed) for allowed in ALLOWED_IPV4_NETWORKS)


def _is_allowed_ipv6(ip: ipaddress.IPv6Address) -> bool:
    return any(ip in network for network in ALLOWED_IPV6_NETWORKS)


def validate_target_ip(target: str) -> ValidationResult:
    """Validate one explicitly allowed IPv4 or IPv6 lab/local target."""
    value = target.strip()
    address = value.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ValidationResult(
            False,
            error=(
                "Use a valid literal IPv4 or IPv6 address, for example "
                "192.168.1.1 or fd00::1"
            ),
        )

    if isinstance(ip, ipaddress.IPv4Address):
        if "%" in value:
            return ValidationResult(
                False,
                error="IPv4 addresses cannot include an interface scope.",
            )
        if not _is_allowed_ipv4(ip):
            return ValidationResult(
                False,
                error="For safety, NetWatch only scans approved local IPv4 ranges.",
            )
        return ValidationResult(True, value=str(ip))

    if not _is_allowed_ipv6(ip):
        return ValidationResult(
            False,
            error="For safety, NetWatch only scans approved local IPv6 ranges.",
        )

    if "%" in value:
        host, scope = value.split("%", 1)
        if (
            not scope
            or len(scope) > 64
            or any(not (character.isalnum() or character in "_.:-") for character in scope)
        ):
            return ValidationResult(
                False,
                error="Invalid IPv6 interface scope identifier.",
            )
        if not ip.is_link_local:
            return ValidationResult(
                False,
                error="IPv6 interface scopes are only accepted for link-local targets.",
            )
        return ValidationResult(True, value=f"{host.lower()}%{scope}")

    return ValidationResult(True, value=str(ip))


def _usable_host_count(network: ipaddress.IPv4Network) -> int:
    """Return an approximate usable-host count without iterating over every IP."""
    if network.prefixlen <= 30:
        return max(network.num_addresses - 2, 0)
    return network.num_addresses


def validate_cidr(cidr: str) -> ValidationResult:
    """Validate an IPv4 CIDR and enforce conservative scope and size limits."""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return ValidationResult(False, error="Invalid IPv4 CIDR. Example: 192.168.1.0/24")

    if not isinstance(network, ipaddress.IPv4Network):
        return ValidationResult(
            False, error="IPv6 network scanning is not supported in this version."
        )

    if not _is_allowed_ipv4_network(network):
        return ValidationResult(False, error="Only approved local IPv4 networks are allowed.")

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
