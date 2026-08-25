from __future__ import annotations

from collections.abc import Mapping


VALID_STATES = ("new", "active", "stale", "retired")


def lifecycle_state(*, last_seen: int | None, now: int, stale_after: int = 86400, retire_after: int = 604800) -> str:
    """Classify inventory freshness without performing I/O."""
    if last_seen is None:
        return "new"
    age = max(0, int(now) - int(last_seen))
    if age >= retire_after:
        return "retired"
    if age >= stale_after:
        return "stale"
    return "active"


def lifecycle_summary(assets: list[Mapping[str, object]], *, now: int) -> dict[str, int]:
    summary = {state: 0 for state in VALID_STATES}
    for asset in assets:
        state = lifecycle_state(last_seen=asset.get("last_seen") if isinstance(asset.get("last_seen"), int) else None, now=now)
        summary[state] += 1
    return summary
