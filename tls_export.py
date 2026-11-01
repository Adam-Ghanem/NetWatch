"""Allowlisted, bounded export of already-retained TLS change evidence."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, Literal

import pandas as pd

from export_utils import safe_csv_bytes

TLS_EXPORT_SCHEMA_VERSION = "netwatch.tls-change.v1"
TLS_EXPORT_EVIDENCE_SOURCE = "retained_tls_service_metadata"
TLS_EXPORT_MAX_ROWS = 1_000

_EVENT_FIELDS = (
    "scan_run_id",
    "observed_at",
    "ip_address",
    "port",
    "protocol",
    "change_type",
    "severity",
    "summary",
    "previous",
    "current",
    "alert_recommended",
    "alert_severity",
    "alert_reason",
)
_CSV_FIELDS = ("schema_version", "evidence_source", *_EVENT_FIELDS)
_TEXT_LIMITS = {
    "observed_at": 64,
    "ip_address": 45,
    "protocol": 16,
    "change_type": 64,
    "severity": 16,
    "summary": 512,
    "previous": 512,
    "current": 512,
    "alert_severity": 16,
    "alert_reason": 512,
}


def _safe_number(value: object, *, maximum: int) -> int:
    if isinstance(value, bool):
        return 0
    try:
        result = int(str(value))
    except (ValueError, TypeError):
        return 0
    return max(0, min(result, maximum))


def _safe_event(source: Mapping[str, Any]) -> dict[str, object]:
    """Never pass through arbitrary stored fields or provider-supplied material."""
    row: dict[str, object] = {}
    for field in _EVENT_FIELDS:
        if field == "alert_recommended":
            row[field] = source.get(field) is True
        elif field == "port":
            row[field] = _safe_number(source.get(field), maximum=65_535)
        elif field == "scan_run_id":
            row[field] = _safe_number(source.get(field), maximum=2_147_483_647)
        else:
            value = source.get(field)
            if not isinstance(value, (str, int, float)) or isinstance(value, bool):
                value = ""
            row[field] = str(value).strip()[: _TEXT_LIMITS[field]]
    return row


def _safe_rows(snapshot: Mapping[str, Any], *, limit: int) -> list[dict[str, object]]:
    if not 1 <= limit <= TLS_EXPORT_MAX_ROWS:
        raise ValueError("TLS export limit must be between 1 and 1,000.")
    items = snapshot.get("items", [])
    if not isinstance(items, list):
        raise ValueError("TLS export requires a list of retained change events.")
    rows: list[dict[str, object]] = []
    for item in items[:limit]:
        if not isinstance(item, dict):
            continue
        rows.append(_safe_event(item))
    return rows


def export_tls_investigator(
    snapshot: Mapping[str, Any],
    *,
    export_format: Literal["json", "csv", "ndjson"],
    limit: int = 100,
) -> bytes:
    """Serialize the same filtered evidence visible in the authenticated investigator.

    IP addresses and SHA-256 certificate fingerprints can be included as evidence.
    Certificate bodies, subject/issuer identities and secrets are never exported.
    """
    rows = _safe_rows(snapshot, limit=limit)
    if export_format == "csv":
        csv_rows = [
            {
                "schema_version": TLS_EXPORT_SCHEMA_VERSION,
                "evidence_source": TLS_EXPORT_EVIDENCE_SOURCE,
                **row,
            }
            for row in rows
        ]
        return safe_csv_bytes(pd.DataFrame(csv_rows, columns=_CSV_FIELDS))

    if export_format == "ndjson":
        return (
            "".join(
                json.dumps(
                    {
                        "schema_version": TLS_EXPORT_SCHEMA_VERSION,
                        "evidence_source": TLS_EXPORT_EVIDENCE_SOURCE,
                        **row,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
                for row in rows
            )
        ).encode("utf-8")

    if export_format != "json":
        raise ValueError("Unsupported TLS evidence export format.")
    payload = {
        "schema_version": TLS_EXPORT_SCHEMA_VERSION,
        "evidence_source": TLS_EXPORT_EVIDENCE_SOURCE,
        "count": len(rows),
        "privacy": {
            "ip_addresses_included": True,
            "certificate_bodies_retained": False,
            "certificate_identity_fields_retained": False,
            "network_probes_added": False,
        },
        "events": rows,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
