from __future__ import annotations

from collections.abc import Mapping


def device_health(asset: Mapping[str, object]) -> dict[str, object]:
    """Return a conservative health summary from inventory evidence."""
    checks = {
        "identity": bool(asset.get("hostname") or asset.get("manufacturer") or asset.get("mac")),
        "addressing": bool(asset.get("ip")),
        "services": bool(asset.get("services")),
    }
    score = round(sum(checks.values()) / len(checks) * 100)
    return {"score": score, "status": "healthy" if score >= 67 else "incomplete", "checks": checks}
