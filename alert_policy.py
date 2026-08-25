from __future__ import annotations

from collections.abc import Mapping


def should_alert(finding: Mapping[str, object], *, minimum_severity: str = "high") -> bool:
    """Apply a small deterministic alert gate to an already validated finding."""
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    severity = str(finding.get("severity", "low")).lower()
    threshold = str(minimum_severity).lower()
    if severity not in order or threshold not in order:
        return False
    if not finding.get("evidence"):
        return False
    return order[severity] >= order[threshold]
