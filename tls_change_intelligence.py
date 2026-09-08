from __future__ import annotations

import alert_policy
from intelligence_store import recent_tls_service_history
from tls_cipher_posture import is_confirmed_cipher_regression

_TLS_PROTOCOL_RANK = {
    "sslv3": 0,
    "tlsv1": 1,
    "tlsv1.0": 1,
    "tlsv1.1": 2,
    "tlsv1.2": 3,
    "tlsv1.3": 4,
}
_TLS_CHANGE_TYPES = {
    "certificate_rotated",
    "tls_protocol_downgrade",
    "tls_protocol_changed",
    "tls_cipher_regression",
    "tls_cipher_changed",
    "tls_alpn_changed",
    "certificate_validity_risk",
    "certificate_expiry_risk",
}
_TLS_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_TLS_TRANSPORT_PROTOCOLS = {"TCP", "UDP"}


def _text(value: object) -> str:
    return str(value or "").strip()


def _integer(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return default
        try:
            return int(raw)
        except ValueError:
            return default
    return default


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


def _apply_alert_policy(
    changes: list[dict[str, object]],
    *,
    minimum_severity: str,
) -> None:
    """Attach deterministic alert recommendations without inventing new TLS evidence."""
    for change in changes:
        summary = _text(change.get("summary"))
        severity = _text(change.get("severity")) or "info"
        recommended = alert_policy.should_alert(
            {"severity": severity, "evidence": summary},
            minimum_severity=minimum_severity,
        )
        change["alert_recommended"] = recommended
        change["alert_severity"] = severity
        change["alert_reason"] = summary if recommended else ""


def _normalize_investigator_filters(
    *,
    port: int | None,
    protocol: str | None,
    change_type: str | None,
    severity: str | None,
) -> tuple[int | None, str | None, str | None, str | None]:
    normalized_port = port
    if normalized_port is not None and not 1 <= normalized_port <= 65535:
        raise ValueError("TLS investigator port must be between 1 and 65535.")

    normalized_protocol: str | None = None
    if protocol is not None:
        normalized_protocol = _text(protocol).upper()
        if normalized_protocol not in _TLS_TRANSPORT_PROTOCOLS:
            raise ValueError("TLS investigator protocol must be TCP or UDP.")

    normalized_change_type: str | None = None
    if change_type is not None:
        normalized_change_type = _text(change_type).lower()
        if normalized_change_type not in _TLS_CHANGE_TYPES:
            raise ValueError("TLS investigator change type is not supported.")

    normalized_severity: str | None = None
    if severity is not None:
        normalized_severity = _text(severity).lower()
        if normalized_severity not in _TLS_SEVERITIES:
            raise ValueError("TLS investigator severity is not supported.")

    return normalized_port, normalized_protocol, normalized_change_type, normalized_severity


def _filter_investigator_changes(
    changes: list[dict[str, object]],
    *,
    port: int | None,
    protocol: str | None,
    change_type: str | None,
    severity: str | None,
    alerts_only: bool,
) -> list[dict[str, object]]:
    filtered: list[dict[str, object]] = []
    for change in changes:
        if port is not None and _integer(change.get("port")) != port:
            continue
        if protocol is not None and _text(change.get("protocol")).upper() != protocol:
            continue
        if change_type is not None and _text(change.get("change_type")).lower() != change_type:
            continue
        if severity is not None and _text(change.get("severity")).lower() != severity:
            continue
        if alerts_only and change.get("alert_recommended") is not True:
            continue
        filtered.append(change)
    return filtered


def analyze_tls_service_changes(
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
) -> list[dict[str, object]]:
    """Derive evidence-safe TLS transitions from normalized historical observations.

    The analyzer is intentionally conservative: it only compares consecutive observations
    for the same IP/protocol/port tuple and does not infer certificate identity, compromise,
    or cipher weakness from unfamiliar names. A cipher regression is raised only for a
    known-modern AEAD -> known-legacy transition. Alert recommendations are derived only
    from the already-classified evidence. Optional investigator pivots filter only derived
    evidence; they never trigger new probes.
    """
    safe_limit = max(1, min(int(limit), 1_000))
    warning_days = max(1, min(int(expiry_warning_days), 365))
    (
        normalized_port,
        normalized_protocol,
        normalized_change_type,
        normalized_severity,
    ) = _normalize_investigator_filters(
        port=port,
        protocol=protocol,
        change_type=change_type,
        severity=severity,
    )
    previous_by_service: dict[tuple[str, str, int], dict[str, object]] = {}
    changes: list[dict[str, object]] = []

    ordered = sorted(
        history,
        key=lambda row: (
            _text(row.get("observed_at")),
            _integer(row.get("scan_run_id", 0)),
        ),
    )
    for current in ordered:
        current_port = _integer(current.get("port", 0))
        ip_address = _text(current.get("ip_address"))
        current_protocol = (_text(current.get("protocol")) or "TCP").upper()
        if not ip_address or not 1 <= current_port <= 65535:
            continue
        key = (ip_address, current_protocol, current_port)
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

        previous_tls_protocol = _text(previous.get("tls_protocol"))
        current_tls_protocol = _text(current.get("tls_protocol"))
        if (
            previous_tls_protocol
            and current_tls_protocol
            and previous_tls_protocol != current_tls_protocol
        ):
            previous_rank = _TLS_PROTOCOL_RANK.get(previous_tls_protocol.lower())
            current_rank = _TLS_PROTOCOL_RANK.get(current_tls_protocol.lower())
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
                    previous=previous_tls_protocol,
                    current_value=current_tls_protocol,
                )
            )

        previous_cipher = _text(previous.get("tls_cipher"))
        current_cipher = _text(current.get("tls_cipher"))
        if previous_cipher and current_cipher and previous_cipher != current_cipher:
            cipher_regression = is_confirmed_cipher_regression(previous_cipher, current_cipher)
            changes.append(
                _change_event(
                    current,
                    change_type=(
                        "tls_cipher_regression" if cipher_regression else "tls_cipher_changed"
                    ),
                    severity=("high" if cipher_regression else "info"),
                    summary=(
                        "Negotiated TLS cipher regressed from known modern AEAD to a known legacy cipher."
                        if cipher_regression
                        else "Negotiated TLS cipher changed between observations."
                    ),
                    previous=previous_cipher,
                    current_value=current_cipher,
                )
            )

        previous_alpn = _text(previous.get("tls_alpn"))
        current_alpn = _text(current.get("tls_alpn"))
        if previous_alpn and current_alpn and previous_alpn != current_alpn:
            changes.append(
                _change_event(
                    current,
                    change_type="tls_alpn_changed",
                    severity="info",
                    summary="Negotiated TLS application protocol changed between observations.",
                    previous=previous_alpn,
                    current_value=current_alpn,
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

    _apply_alert_policy(changes, minimum_severity=alert_min_severity)
    changes = _filter_investigator_changes(
        changes,
        port=normalized_port,
        protocol=normalized_protocol,
        change_type=normalized_change_type,
        severity=normalized_severity,
        alerts_only=alerts_only,
    )
    changes.sort(
        key=lambda event: (
            _text(event.get("observed_at")),
            _integer(event.get("scan_run_id", 0)),
        ),
        reverse=True,
    )
    return changes[:safe_limit]


def recent_tls_service_changes(
    *,
    limit: int = 100,
    ip_address: str | None = None,
    expiry_warning_days: int = 30,
    alert_min_severity: str = "medium",
    port: int | None = None,
    protocol: str | None = None,
    change_type: str | None = None,
    severity: str | None = None,
    alerts_only: bool = False,
) -> list[dict[str, object]]:
    """Return bounded TLS rotation, negotiation-change, expiry-risk and alert evidence."""
    safe_limit = max(1, min(int(limit), 1_000))
    history_limit = min(1_000, max(100, safe_limit * 4))
    history = recent_tls_service_history(limit=history_limit, ip_address=ip_address)
    return analyze_tls_service_changes(
        history,
        limit=safe_limit,
        expiry_warning_days=expiry_warning_days,
        alert_min_severity=alert_min_severity,
        port=port,
        protocol=protocol,
        change_type=change_type,
        severity=severity,
        alerts_only=alerts_only,
    )
