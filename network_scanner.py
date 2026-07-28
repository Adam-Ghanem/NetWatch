from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from config import MAX_WORKERS
from device_identity import discover_device_identity, infer_device_identity
from host_profiler import parse_ttl
from ping_checker import ping_host
from security import validate_cidr


def _scan_host(ip: str) -> dict | None:
    online, message = ping_host(ip)
    if not online:
        return None

    ttl = parse_ttl(message)
    try:
        identity = discover_device_identity(ip, ttl=ttl)
    except Exception:  # pragma: no cover - identity evidence is best effort
        identity = infer_device_identity(ip, ttl=ttl)
    return {
        "IP Address": ip,
        "Status": "Online",
        "Details": message,
        **identity.as_scan_fields(),
    }


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
        future_map = {executor.submit(_scan_host, ip): ip for ip in hosts}
        for future in as_completed(future_map):
            try:
                row = future.result()
            except Exception:  # pragma: no cover - one host must not fail the scan
                row = None
            if row is not None:
                results.append(row)

    return sorted(results, key=lambda row: ipaddress.ip_address(row["IP Address"]))
