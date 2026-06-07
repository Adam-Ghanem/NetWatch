from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

RISK_WEIGHT = {
    "High": 4,
    "Medium": 2,
    "Low": 1,
    "None": 0,
}


@dataclass(frozen=True)
class RiskSummary:
    checked: int
    open_ports: int
    high: int
    medium: int
    low: int
    score: int
    level: str


def exposure_level(score: int) -> str:
    if score >= 12:
        return "High"
    if score >= 5:
        return "Medium"
    if score > 0:
        return "Low"
    return "Clean"


def summarize_exposure(rows: Iterable[dict]) -> RiskSummary:
    items = list(rows)
    open_items = [row for row in items if row.get("Status") == "Open"]
    high = sum(1 for row in open_items if row.get("Risk") == "High")
    medium = sum(1 for row in open_items if row.get("Risk") == "Medium")
    low = sum(1 for row in open_items if row.get("Risk") == "Low")
    score = sum(RISK_WEIGHT.get(str(row.get("Risk", "None")), 0) for row in open_items)

    return RiskSummary(
        checked=len(items),
        open_ports=len(open_items),
        high=high,
        medium=medium,
        low=low,
        score=score,
        level=exposure_level(score),
    )


def top_recommendations(rows: Iterable[dict], limit: int = 5) -> list[dict]:
    open_items = [row for row in rows if row.get("Status") == "Open"]
    sorted_items = sorted(
        open_items,
        key=lambda row: RISK_WEIGHT.get(str(row.get("Risk", "None")), 0),
        reverse=True,
    )
    return sorted_items[:limit]


def risk_badge(level: str) -> str:
    badges = {
        "Clean": "No open services in the checked list",
        "Low": "Low exposure; review optional services",
        "Medium": "Medium exposure; verify firewall and auth",
        "High": "High exposure; review access quickly",
    }
    return badges.get(level, "Review findings")
