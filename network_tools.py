from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from config import MAX_HOSTS_PER_SCAN
from security import validate_cidr


@dataclass(frozen=True)
class NetworkProfile:
    cidr: str
    version: int
    network_address: str
    broadcast_address: str
    netmask: str
    prefix_length: int
    usable_hosts: int
    first_hosts: list[str]
    scan_allowed: bool
    message: str


def usable_host_count(network: ipaddress._BaseNetwork) -> int:
    if network.version == 4 and network.prefixlen <= 30:
        return max(network.num_addresses - 2, 0)
    return network.num_addresses


def network_profile(cidr: str, sample_size: int = 8) -> NetworkProfile:
    validation = validate_cidr(cidr)
    if not validation.ok:
        return NetworkProfile(
            cidr=cidr,
            version=0,
            network_address="-",
            broadcast_address="-",
            netmask="-",
            prefix_length=0,
            usable_hosts=0,
            first_hosts=[],
            scan_allowed=False,
            message=validation.error or "Invalid CIDR",
        )

    network = ipaddress.ip_network(validation.value, strict=False)
    hosts = [str(host) for _, host in zip(range(sample_size), network.hosts())]
    host_count = usable_host_count(network)
    allowed = host_count <= MAX_HOSTS_PER_SCAN

    return NetworkProfile(
        cidr=str(network),
        version=network.version,
        network_address=str(network.network_address),
        broadcast_address=str(network.broadcast_address),
        netmask=str(network.netmask),
        prefix_length=network.prefixlen,
        usable_hosts=host_count,
        first_hosts=hosts,
        scan_allowed=allowed,
        message="Ready for local scan" if allowed else f"Too large for scan limit ({MAX_HOSTS_PER_SCAN})",
    )


def guess_gateway(cidr: str) -> str:
    profile = network_profile(cidr, sample_size=2)
    if not profile.first_hosts:
        return "-"
    return profile.first_hosts[0]
