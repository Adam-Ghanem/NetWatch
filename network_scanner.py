from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from config import HOSTNAME_LOOKUP_ENABLED, MAX_WORKERS
from device_identity import enrich_host_rows
from ping_checker import ping_host
from security import validate_cidr


def scan_network(cidr: str, max_workers: int = MAX_WORKERS) -> List[dict]:
    """Ping-sweep a validated private/local CIDR network and return online hosts."""
    validation = validate_cidr(cidr)
    if not validation.ok:
        raise ValueError(validation.error or "Invalid CIDR")

    network = ipaddress.ip_network(validation.value or cidr, strict=False)
    hosts = [str(ip) for ip in network.hosts()]
    results: List[dict] = []
    if not hosts:
        return results

    worker_count = max(1, min(int(max_workers), MAX_WORKERS, len(hosts)))

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(ping_host, ip): ip for ip in hosts}
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                online, message = future.result()
            except Exception as exc:  # pragma: no cover
                online, message = False, str(exc)
            if online:
                results.append({"IP Address": ip, "Status": "Online", "Details": message})

    ordered = sorted(results, key=lambda row: ipaddress.ip_address(row["IP Address"]))
    return enrich_host_rows(ordered, resolve_hostnames=HOSTNAME_LOOKUP_ENABLED)
