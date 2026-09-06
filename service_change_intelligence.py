from __future__ import annotations

import ipaddress
from collections.abc import Iterable

import inventory_store


def _service_target(ip_address: str, port: int, protocol: str) -> str:
    address = ipaddress.ip_address(ip_address)
    host = f"[{address}]" if address.version == 6 else str(address)
    return f"{host}:{port}/{protocol.lower()}"


def _identity(row: dict) -> tuple[str, str]:
    return (
        str(row.get("service_product", "")).strip(),
        str(row.get("service_version", "")).strip(),
    )


def build_service_version_changes(
    findings: Iterable[dict],
    *,
    limit: int = 100,
) -> list[dict]:
    """Build bounded old→new software transitions from persisted service evidence."""
    safe_limit = max(1, min(int(limit), 200))
    ordered = sorted(
        (dict(row) for row in findings if isinstance(row, dict)),
        key=lambda row: (str(row.get("observed_at", "")), int(row.get("scan_run_id", 0))),
    )
    previous_by_service: dict[tuple[str, int, str], dict] = {}
    changes: list[dict] = []

    for row in ordered:
        if str(row.get("status", "")).lower() != "open":
            continue
        try:
            port = int(row.get("port", 0))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65_535:
            continue
        protocol = str(row.get("protocol", "TCP")).strip().upper() or "TCP"
        service = str(row.get("service", "")).strip()
        product, version = _identity(row)
        if not product and not version:
            continue

        key = (service.casefold(), port, protocol)
        previous = previous_by_service.get(key)
        previous_by_service[key] = row
        if previous is None:
            continue

        old_product, old_version = _identity(previous)
        if (old_product, old_version) == (product, version):
            continue

        ip_address = str(row.get("ip_address", "")).strip()
        try:
            target = _service_target(ip_address, port, protocol)
        except ValueError:
            continue
        changes.append(
            {
                "created_at": str(row.get("observed_at", "")),
                "kind": "service_version_change",
                "event_type": "service_version_change",
                "event_label": "Service version changed",
                "details": f"{old_product} {old_version} → {product} {version}".strip(),
                "scan_run_id": row.get("scan_run_id"),
                "status": str(row.get("status", "")),
                "target": target,
                "service": service,
                "service_detection": str(row.get("service_detection", "")),
                "service_confidence": str(row.get("service_confidence", "")),
                "old_product": old_product,
                "old_version": old_version,
                "new_product": product,
                "new_version": version,
            }
        )

    changes.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return changes[:safe_limit]


def asset_service_version_changes(ip_address: str, *, limit: int = 100) -> list[dict]:
    """Return passive version-change intelligence for one retained asset."""
    safe_limit = max(1, min(int(limit), 200))
    findings = inventory_store.recent_service_findings(
        limit=min(1_000, max(safe_limit * 10, 20)),
        ip_address=ip_address,
    )
    return build_service_version_changes(findings, limit=safe_limit)
