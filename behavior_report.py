from __future__ import annotations

from collections.abc import Iterable, Mapping


def summarize_behavior(findings: Iterable[Mapping[str, object]]) -> dict[str, object]:
    """Build a stable, explainable summary from behavioral findings."""
    items = [dict(item) for item in findings]
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    kinds: dict[str, int] = {}
    for item in items:
        severity = str(item.get("severity", "low")).lower()
        if severity in counts:
            counts[severity] += 1
        kind = str(item.get("kind", item.get("type", "unknown")))
        kinds[kind] = kinds.get(kind, 0) + 1
    risk = min(100, counts["critical"] * 40 + counts["high"] * 20 + counts["medium"] * 8 + counts["low"] * 2)
    return {"total": len(items), "severity": counts, "by_kind": dict(sorted(kinds.items())), "risk_score": risk}
