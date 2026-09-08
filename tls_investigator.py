from __future__ import annotations

from collections import Counter
from typing import Any, Iterable

from intelligence_store import recent_tls_service_history
from tls_change_intelligence import analyze_tls_service_changes

_MAX_HISTORY_ROWS = 1_000
_MAX_CHANGE_ROWS = 1_000


def _text(value: object) -> str:
    return str(value or "").strip()


def _integer(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _bounded_limit(value: int, *, minimum: int, maximum: int) -> int:
    return max(minimum, min(int(value), maximum))


def _service_key(row: dict[str, object]) -> tuple[str, str, int] | None:
    ip_address = _text(row.get("ip_address"))
    protocol = (_text(row.get("protocol")) or "TCP").upper()
    port = _integer(row.get("port"))
    if not ip_address or not 1 <= port <= 65_535:
        return None
    return ip_address, protocol, port


def _facet_counts(
    changes: Iterable[dict[str, object]],
    field: str,
) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for change in changes:
        value = _text(change.get(field)).lower()
        if value:
            counts[value] += 1
    return dict(sorted(counts.items()))


def build_tls_investigator_snapshot(
    history: list[dict[str, object]],
    *,
    limit: int = 100,
    expiry_warning_days: int = 30,
    alert_min_severity: str = "medium",
    port: int | None = None,
    protocol: str | None = None,
    change_type: str | None = None,
    severity: str | None = None,
    alerts_only: bool = False,
) -> dict[str, Any]:
    """Build a bounded, privacy-preserving TLS investigator view from retained evidence.

    The snapshot does not collect certificate bodies or identity fields and never triggers
    network probes. Facets describe only the filtered change set returned to the caller so
    dashboard/API consumers cannot accidentally display stale counts from a broader scope.
    """
    safe_limit = _bounded_limit(limit, minimum=1, maximum=_MAX_CHANGE_ROWS)
    bounded_history = list(history[:_MAX_HISTORY_ROWS])
    changes = analyze_tls_service_changes(
        bounded_history,
        limit=safe_limit,
        expiry_warning_days=expiry_warning_days,
        alert_min_severity=alert_min_severity,
        port=port,
        protocol=protocol,
        change_type=change_type,
        severity=severity,
        alerts_only=alerts_only,
    )
    services: set[tuple[str, str, int]] = set()
    for row in bounded_history:
        key = _service_key(row)
        if key is not None:
            services.add(key)
    alert_count = sum(change.get("alert_recommended") is True for change in changes)
    return {
        "history_count": len(bounded_history),
        "service_count": len(services),
        "change_count": len(changes),
        "alert_recommended_count": alert_count,
        "facets": {
            "change_types": _facet_counts(changes, "change_type"),
            "severities": _facet_counts(changes, "severity"),
        },
        "items": changes,
        "evidence_scope": {
            "source": "retained_tls_service_metadata",
            "network_probes_added": False,
            "certificate_bodies_retained": False,
            "certificate_identity_fields_retained": False,
        },
    }


def recent_tls_investigator_snapshot(
    *,
    history_limit: int = 400,
    limit: int = 100,
    ip_address: str | None = None,
    expiry_warning_days: int = 30,
    alert_min_severity: str = "medium",
    port: int | None = None,
    protocol: str | None = None,
    change_type: str | None = None,
    severity: str | None = None,
    alerts_only: bool = False,
) -> dict[str, Any]:
    """Load bounded retained TLS evidence and return an investigator-ready snapshot."""
    safe_history_limit = _bounded_limit(
        history_limit,
        minimum=2,
        maximum=_MAX_HISTORY_ROWS,
    )
    history = recent_tls_service_history(
        limit=safe_history_limit,
        ip_address=ip_address,
    )
    return build_tls_investigator_snapshot(
        history,
        limit=limit,
        expiry_warning_days=expiry_warning_days,
        alert_min_severity=alert_min_severity,
        port=port,
        protocol=protocol,
        change_type=change_type,
        severity=severity,
        alerts_only=alerts_only,
    )
