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


def _change_details(
    old_product: str,
    old_version: str,
    new_product: str,
    new_version: str,
    detection: str,
    confidence: str,
) -> str:
    details = [f"{old_product} {old_version} → {new_product} {new_version}".strip()]
    if detection:
        details.append(detection)
    if confidence:
        details.append(f"{confidence} confidence")
    return " · ".join(details)


def _normalized_status(row: dict) -> str:
    return " ".join(str(row.get("status", "Unknown")).split())[:40] or "Unknown"


def _status_change_details(old_status: str, new_status: str, detection: str) -> str:
    if new_status.casefold() == "open":
        details = f"Reachability changed from {old_status} to Open."
    else:
        details = (
            f"The service was previously confirmed Open; the latest observation is "
            f"{new_status}. This does not by itself prove the service is down."
        )
    if detection:
        details = f"{details} Evidence: {detection}."
    return details


def _ordered_findings(findings: Iterable[dict]) -> list[dict]:
    return sorted(
        (dict(row) for row in findings if isinstance(row, dict)),
        key=lambda row: (str(row.get("observed_at", "")), int(row.get("scan_run_id", 0))),
    )


def build_service_version_changes(
    findings: Iterable[dict],
    *,
    limit: int = 100,
) -> list[dict]:
    """Build bounded old→new software transitions from persisted service evidence."""
    safe_limit = max(1, min(int(limit), 200))
    ordered = _ordered_findings(findings)
    previous_by_service: dict[tuple[str, int, str], dict] = {}
    changes: list[dict] = []

    for row in ordered:
        if _normalized_status(row).casefold() != "open":
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
        detection = str(row.get("service_detection", "")).strip()
        confidence = str(row.get("service_confidence", "")).strip()
        changes.append(
            {
                "created_at": str(row.get("observed_at", "")),
                "kind": "service_version_change",
                "event_type": "service_version_change",
                "event_label": "Service version changed",
                "details": _change_details(
                    old_product,
                    old_version,
                    product,
                    version,
                    detection,
                    confidence,
                ),
                "scan_run_id": row.get("scan_run_id"),
                "status": _normalized_status(row),
                "target": target,
                "service": service,
                "service_detection": detection,
                "service_confidence": confidence,
                "old_product": old_product,
                "old_version": old_version,
                "new_product": product,
                "new_version": version,
            }
        )

    changes.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return changes[:safe_limit]


def build_service_state_changes(
    findings: Iterable[dict],
    *,
    limit: int = 100,
) -> list[dict]:
    """Build bounded reachability transitions without overstating filtered/timeout evidence."""
    safe_limit = max(1, min(int(limit), 200))
    previous_by_service: dict[tuple[str, int, str], dict] = {}
    changes: list[dict] = []

    for row in _ordered_findings(findings):
        try:
            port = int(row.get("port", 0))
        except (TypeError, ValueError):
            continue
        if not 1 <= port <= 65_535:
            continue

        protocol = str(row.get("protocol", "TCP")).strip().upper() or "TCP"
        service = str(row.get("service", "")).strip()
        status = _normalized_status(row)
        key = (service.casefold(), port, protocol)
        previous = previous_by_service.get(key)
        previous_by_service[key] = row
        if previous is None:
            continue

        old_status = _normalized_status(previous)
        old_open = old_status.casefold() == "open"
        new_open = status.casefold() == "open"
        if old_open == new_open:
            continue

        ip_address = str(row.get("ip_address", "")).strip()
        try:
            target = _service_target(ip_address, port, protocol)
        except ValueError:
            continue

        detection = str(row.get("service_detection", "")).strip()
        if new_open:
            event_type = "service_became_open"
            event_label = "Service became reachable"
        else:
            event_type = "service_open_not_confirmed"
            event_label = "Service no longer confirmed open"

        changes.append(
            {
                "created_at": str(row.get("observed_at", "")),
                "kind": "service_state_change",
                "event_type": event_type,
                "event_label": event_label,
                "details": _status_change_details(old_status, status, detection),
                "scan_run_id": row.get("scan_run_id"),
                "status": status,
                "target": target,
                "service": service,
                "service_detection": detection,
                "old_status": old_status,
                "new_status": status,
            }
        )

    changes.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return changes[:safe_limit]


def _asset_service_changes(ip_address: str, *, limit: int) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    findings = inventory_store.recent_service_findings(
        limit=min(1_000, max(safe_limit * 10, 20)),
        ip_address=ip_address,
    )
    changes = build_service_version_changes(findings, limit=safe_limit)
    changes.extend(build_service_state_changes(findings, limit=safe_limit))
    changes.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)
    return changes[:safe_limit]


def asset_service_version_changes(ip_address: str, *, limit: int = 100) -> list[dict]:
    """Return bounded service-change intelligence for one retained asset timeline.

    The historical function name is retained for compatibility. Results now include both
    software-version changes and evidence-safe reachability transitions.
    """
    return _asset_service_changes(ip_address, limit=limit)


def asset_service_state_changes(ip_address: str, *, limit: int = 100) -> list[dict]:
    """Return only reachability transitions for one retained asset."""
    safe_limit = max(1, min(int(limit), 200))
    findings = inventory_store.recent_service_findings(
        limit=min(1_000, max(safe_limit * 10, 20)),
        ip_address=ip_address,
    )
    return build_service_state_changes(findings, limit=safe_limit)
