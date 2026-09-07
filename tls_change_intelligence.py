from __future__ import annotations

from typing import Any

from intelligence_store import recent_tls_service_history

_TLS_PROTOCOL_RANK = {
    "sslv3": 0,
    "tlsv1": 1,
    "tlsv1.0": 1,
    "tlsv1.1": 2,
    "tlsv1.2": 3,
    "tlsv1.3": 4,
}


def _text(value: object) -> str:
    return str(value or "").strip()


def _days_remaining(value: object) -> int | None:
    raw = _text(value)
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _base_event(current: dict[str, object]) -> dict[str, object]:
    return {
        "scan_run_id": current.get("scan_run_id", 0),
        "ip_address": _text(current.get("ip_address")),
        "port": current.get("port", 0),
        "protocol": _text(current.get("protocol")) or "TCP",
        "observed_at": _text(current.get("observed_at")),
    }


def _change_event(
    current: dict[str, object],
    *,
    change_type: str,
    severity: str,
    summary: str,
    previous: object,
    current_value: object,
) -> dict[str, object]:
    return {
        **_base_event(current),
        "change_type": change_type,
        "severity": severity,
        "summary": summary,
        "previous": _text(previous),
        "current": _text(current_value),
    }


def analyze_tls_service_changes(
    history: list[dict[str, object]],
    *,
    limit: int = 100,
    expiry_warning_days: int = 30,
) -> list[dict[str, object]]:
    """Derive evidence-safe TLS transitions from normalized historical observations.

    The analyzer is intentionally conservative: it only compares consecutive observations
    for the same IP/protocol/port tuple and does not infer certificate identity, compromise,
    or cipher weakness from names alone.
    """
    safe_limit = max(1, min(int(limit), 1_000))
    warning_days = max(1, min(int(expiry_warning_days), 365))
    previous_by_service: dict[tuple[str, str, int], dict[str, object]] = {}
    changes: list[dict[str, object]] = []

    ordered = sorted(
        history,
        key=lambda row: (
            _text(row.get("observed_at")),
            int(row.get("scan_run_id", 0) or 0),
        ),
    )
    for current in ordered:
        try:
            port = int(current.get("port", 0) or 0)
        except (TypeError, ValueError):
            continue
        ip_address = _text(current.get("ip_address"))
        protocol = (_text(current.get("protocol")) or "TCP").upper()
        if not ip_address or not 1 <= port <= 65535:
            continue
        key = (ip_address, protocol, port)
        previous = previous_by_service.get(key)
        previous_by_service[key] = current
        if previous is None:
            continue

        previous_fingerprint = _text(previous.get("certificate_sha256")).lower()
        current_fingerprint = _text(current.get("certificate_sha256")).lower()
        if (
            len(previous_fingerprint) == 64
            and len(current_fingerprint) == 64
            and previous_fingerprint != current_fingerprint
        ):
            changes.append(
                _change_event(
                    current,
                    change_type="certificate_rotated",
                    severity="info",
                    summary="TLS certificate fingerprint changed between confirmed observations.",
                    previous=previous_fingerprint,
                    current_value=current_fingerprint,
                )
            )

        previous_protocol = _text(previous.get("tls_protocol"))
        current_protocol = _text(current.get("tls_protocol"))
        if previous_protocol and current_protocol and previous_protocol != current_protocol:
            previous_rank = _TLS_PROTOCOL_RANK.get(previous_protocol.lower())
            current_rank = _TLS_PROTOCOL_RANK.get(current_protocol.lower())
            downgrade = (
                previous_rank is not None
                and current_rank is not None
                and current_rank < previous_rank
            )
            changes.append(
                _change_event(
                    current,
                    change_type=("tls_protocol_downgrade" if downgrade else "tls_protocol_changed"),
                    severity=("high" if downgrade else "info"),
                    summary=(
                        "Negotiated TLS protocol moved to an older known protocol version."
                        if downgrade
                        else "Negotiated TLS protocol changed between observations."
                    ),
                    previous=previous_protocol,
                    current_value=current_protocol,
                )
            )

        previous_cipher = _text(previous.get("tls_cipher"))
        current_cipher = _text(current.get("tls_cipher"))
        if previous_cipher and current_cipher and previous_cipher != current_cipher:
            changes.append(
                _change_event(
                    current,
                    change_type="tls_cipher_changed",
                    severity="info",
                    summary="Negotiated TLS cipher changed between observations.",
                    previous=previous_cipher,
                    current_value=current_cipher,
                )
            )

        previous_status = _text(previous.get("certificate_status")) or "Unknown"
        current_status = _text(current.get("certificate_status")) or "Unknown"
        previous_days = _days_remaining(previous.get("certificate_days_remaining"))
        current_days = _days_remaining(current.get("certificate_days_remaining"))
        if current_status in {"Expired", "Not Yet Valid"} and current_status != previous_status:
            changes.append(
                _change_event(
                    current,
                    change_type="certificate_validity_risk",
                    severity="high",
                    summary=f"TLS certificate validity status changed to {current_status}.",
                    previous=previous_status,
                    current_value=current_status,
                )
            )
        elif (
            current_status == "Valid"
            and current_days is not None
            and current_days <= warning_days
            and (previous_days is None or previous_days > warning_days)
        ):
            changes.append(
                _change_event(
                    current,
                    change_type="certificate_expiry_risk",
                    severity="medium",
                    summary=(
                        f"TLS certificate entered the {warning_days}-day expiry warning window."
                    ),
                    previous=("" if previous_days is None else previous_days),
                    current_value=current_days,
                )
            )

    changes.sort(
        key=lambda event: (
            _text(event.get("observed_at")),
            int(event.get("scan_run_id", 0) or 0),
        ),
        reverse=True,
    )
    return changes[:safe_limit]


def recent_tls_service_changes(
    *,
    limit: int = 100,
    ip_address: str | None = None,
    expiry_warning_days: int = 30,
) -> list[dict[str, object]]:
    """Return bounded TLS rotation, negotiation-change, and expiry-risk evidence."""
    safe_limit = max(1, min(int(limit), 1_000))
    history_limit = min(1_000, max(100, safe_limit * 4))
    history = recent_tls_service_history(limit=history_limit, ip_address=ip_address)
    return analyze_tls_service_changes(
        history,
        limit=safe_limit,
        expiry_warning_days=expiry_warning_days,
    )
