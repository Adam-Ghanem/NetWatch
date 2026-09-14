from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

SERVICE_EVIDENCE_SCHEMA_VERSION = "netwatch.service.v1"
SERVICE_EVIDENCE_SOURCE = "netwatch.service_observation"


def _required_int(row: Mapping[str, object], field: str) -> int:
    value = row.get(field)
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer") from exc


def _text(row: Mapping[str, object], field: str) -> str:
    value = row.get(field, "")
    return "" if value is None else str(value).strip()


def normalize_service_evidence(row: Mapping[str, object]) -> dict[str, Any]:
    """Normalize one persisted service finding into the stable metadata-only v1 contract."""
    ip_text = _text(row, "ip_address")
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise ValueError("ip_address must be a valid IP address") from exc

    port = _required_int(row, "port")
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")

    scan_run_id = _required_int(row, "scan_run_id")
    if scan_run_id < 0:
        raise ValueError("scan_run_id must be non-negative")

    response_time_value = row.get("response_time_ms")
    response_time_ms = None
    if response_time_value is not None:
        try:
            response_time_ms = float(response_time_value)  # type: ignore[arg-type]
        except (TypeError, ValueError) as exc:
            raise ValueError("response_time_ms must be numeric or null") from exc
        if response_time_ms < 0:
            raise ValueError("response_time_ms must be non-negative")

    return {
        "schema_version": SERVICE_EVIDENCE_SCHEMA_VERSION,
        "evidence_source": SERVICE_EVIDENCE_SOURCE,
        "payload_retained": False,
        "scan_run_id": scan_run_id,
        "observed_at": _text(row, "observed_at"),
        "ip_address": str(address),
        "address_family": "ipv4" if address.version == 4 else "ipv6",
        "port": port,
        "protocol": _text(row, "protocol").upper(),
        "service": _text(row, "service"),
        "service_detection": _text(row, "service_detection"),
        "service_product": _text(row, "service_product"),
        "service_version": _text(row, "service_version"),
        "service_confidence": _text(row, "service_confidence"),
        "status": _text(row, "status"),
        "risk": _text(row, "risk"),
        "response_time_ms": response_time_ms,
    }
