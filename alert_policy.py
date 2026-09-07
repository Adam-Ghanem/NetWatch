from __future__ import annotations

from collections.abc import Mapping

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_HIGH_RISK_REACHABILITY_PORTS = {
    ("TCP", 22): "Remote administration service became reachable",
    ("TCP", 23): "Legacy clear-text remote administration service became reachable",
    ("TCP", 3389): "Remote desktop service became reachable",
    ("TCP", 445): "SMB service became reachable",
    ("TCP", 5900): "Remote desktop/VNC service became reachable",
}


def should_alert(finding: Mapping[str, object], *, minimum_severity: str = "high") -> bool:
    """Apply a small deterministic alert gate to an already validated finding."""
    severity = str(finding.get("severity", "low")).lower()
    threshold = str(minimum_severity).lower()
    if severity not in _SEVERITY_ORDER or threshold not in _SEVERITY_ORDER:
        return False
    if not finding.get("evidence"):
        return False
    return _SEVERITY_ORDER[severity] >= _SEVERITY_ORDER[threshold]


def _coerce_port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def service_reachability_alert(
    change: Mapping[str, object],
    *,
    minimum_severity: str = "high",
) -> dict[str, object]:
    """Return an evidence-gated alert recommendation for a newly reachable service.

    This policy never turns filtered/timeout observations into downtime alerts. It only
    considers transitions that were already classified as ``service_became_open`` and
    uses retained service-risk evidence plus a deliberately small remote-access allowlist.
    """
    if str(change.get("event_type", "")) != "service_became_open":
        return {"recommended": False, "severity": "low", "reason": ""}

    port = _coerce_port(change.get("port", 0))
    if port is None:
        return {"recommended": False, "severity": "low", "reason": ""}
    protocol = str(change.get("protocol", "TCP")).strip().upper() or "TCP"
    risk = str(change.get("risk", "None")).strip().lower()
    evidence = str(change.get("service_detection", "")).strip()

    severity = risk if risk in _SEVERITY_ORDER else "low"
    reason = ""
    sensitive_reason = _HIGH_RISK_REACHABILITY_PORTS.get((protocol, port))
    if sensitive_reason:
        severity = "high" if _SEVERITY_ORDER[severity] < _SEVERITY_ORDER["high"] else severity
        reason = sensitive_reason
    elif severity in {"high", "critical"}:
        reason = "High-risk service became reachable"

    candidate = {"severity": severity, "evidence": evidence or reason}
    recommended = bool(reason) and should_alert(candidate, minimum_severity=minimum_severity)
    return {
        "recommended": recommended,
        "severity": severity,
        "reason": reason if recommended else "",
    }
