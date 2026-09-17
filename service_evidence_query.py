from __future__ import annotations

import inventory_store
from service_evidence import (
    MAX_SERVICE_EVIDENCE_RECORDS,
    export_service_evidence_csv,
    export_service_evidence_json,
)


def export_recent_service_evidence(
    *,
    output_format: str = "json",
    limit: int = 200,
    scan_run_id: int | None = None,
    ip_address: str | None = None,
) -> str:
    """Export a bounded, filtered view of persisted service evidence.

    This is a read-only composition boundary: it reuses the inventory store's
    existing scan/IP filters and the stable metadata-only service serializers.
    It performs no network activity and never widens the 1,000-record export cap.
    """
    if isinstance(limit, bool) or not 1 <= limit <= MAX_SERVICE_EVIDENCE_RECORDS:
        raise ValueError(f"limit must be between 1 and {MAX_SERVICE_EVIDENCE_RECORDS}")
    if output_format not in {"json", "csv"}:
        raise ValueError("output_format must be 'json' or 'csv'")

    rows = inventory_store.recent_service_findings(
        limit=limit,
        scan_run_id=scan_run_id,
        ip_address=ip_address,
    )
    if output_format == "csv":
        return export_service_evidence_csv(rows, limit=limit)
    return export_service_evidence_json(rows, limit=limit)
