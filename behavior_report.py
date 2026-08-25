from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TypedDict


class SeverityCounts(TypedDict):
    critical: int
    high: int
    medium: int
    low: int


class BehaviorSummary(TypedDict):
    total: int
    severity: SeverityCounts
    by_kind: dict[str, int]
    risk_score: int


def summarize_behavior(findings: Iterable[Mapping[str, object]]) -> BehaviorSummary:
    """Build a stable, explainable summary from behavioral findings."""
    items = [dict(item) for item in findings]
    counts: SeverityCounts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    kinds: dict[str, int] = {}
    for item in items:
        severity = str(item.get("severity", "low")).lower()
        if severity == "critical":
            counts["critical"] += 1
        elif severity == "high":
            counts["high"] += 1
        elif severity == "medium":
            counts["medium"] += 1
        elif severity == "low":
            counts["low"] += 1
        kind = str(item.get("kind", item.get("type", "unknown")))
        kinds[kind] = kinds.get(kind, 0) + 1
    risk = min(
        100,
        counts["critical"] * 40 + counts["high"] * 20 + counts["medium"] * 8 + counts["low"] * 2,
    )
    return {
        "total": len(items),
        "severity": counts,
        "by_kind": dict(sorted(kinds.items())),
        "risk_score": risk,
    }
