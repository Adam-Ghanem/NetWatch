from __future__ import annotations

import csv
import io
import ipaddress
import json
from collections.abc import Iterable, Mapping
from typing import Any

SERVICE_EVIDENCE_SCHEMA_VERSION = "netwatch.service.v1"
SERVICE_EVIDENCE_SOURCE = "netwatch.service_observation"
MAX_SERVICE_EVIDENCE_RECORDS = 1_000
_NUMERIC_TYPES = (int, float, str, bytes, bytearray)
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")
_CSV_CONTROL_PREFIXES = ("\t", "\r", "\n")
SERVICE_EVIDENCE_FIELDS = (
    "schema_version",
    "evidence_source",
    "payload_retained",
    "scan_run_id",
    "observed_at",
    "ip_address",
    "address_family",
    "port",
    "protocol",
    "service",
    "service_detection",
    "service_product",
    "service_version",
    "service_confidence",
    "status",
    "risk",
    "response_time_ms",
)


def _required_int(row: Mapping[str, object], field: str) -> int:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, _NUMERIC_TYPES):
        raise ValueError(f"{field} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an integer") from exc


def _optional_float(row: Mapping[str, object], field: str) -> float | None:
    value = row.get(field)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, _NUMERIC_TYPES):
        raise ValueError(f"{field} must be numeric or null")
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be numeric or null") from exc
    if result < 0:
        raise ValueError(f"{field} must be non-negative")
    return result


def _text(row: Mapping[str, object], field: str) -> str:
    value = row.get(field, "")
    return "" if value is None else str(value).strip()


def _safe_csv_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    candidate = value.lstrip()
    if value.startswith(_CSV_CONTROL_PREFIXES) or candidate.startswith(
        _CSV_FORMULA_PREFIXES
    ):
        return "'" + value
    return value


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
        "response_time_ms": _optional_float(row, "response_time_ms"),
    }


def normalize_service_evidence_rows(
    rows: Iterable[Mapping[str, object]],
    *,
    limit: int = MAX_SERVICE_EVIDENCE_RECORDS,
) -> list[dict[str, Any]]:
    """Normalize a bounded service-evidence batch for export/API integration."""
    if isinstance(limit, bool) or not 1 <= limit <= MAX_SERVICE_EVIDENCE_RECORDS:
        raise ValueError(f"limit must be between 1 and {MAX_SERVICE_EVIDENCE_RECORDS}")

    normalized: list[dict[str, Any]] = []
    for row in rows:
        if len(normalized) >= limit:
            break
        normalized.append(normalize_service_evidence(row))
    return normalized


def export_service_evidence_json(
    rows: Iterable[Mapping[str, object]],
    *,
    limit: int = MAX_SERVICE_EVIDENCE_RECORDS,
) -> str:
    """Serialize bounded service evidence as a versioned metadata-only JSON envelope."""
    records = normalize_service_evidence_rows(rows, limit=limit)
    return json.dumps(
        {
            "schema_version": SERVICE_EVIDENCE_SCHEMA_VERSION,
            "evidence_source": SERVICE_EVIDENCE_SOURCE,
            "payload_retained": False,
            "count": len(records),
            "items": records,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def export_service_evidence_csv(
    rows: Iterable[Mapping[str, object]],
    *,
    limit: int = MAX_SERVICE_EVIDENCE_RECORDS,
) -> str:
    """Serialize bounded service evidence as spreadsheet-safe UTF-8 CSV."""
    records = normalize_service_evidence_rows(rows, limit=limit)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=SERVICE_EVIDENCE_FIELDS,
        extrasaction="ignore",
    )
    writer.writeheader()
    for record in records:
        writer.writerow(
            {field: _safe_csv_cell(record.get(field)) for field in SERVICE_EVIDENCE_FIELDS}
        )
    return output.getvalue()
