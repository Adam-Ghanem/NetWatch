from __future__ import annotations

from collections.abc import Iterable, Mapping


def changes_in_window(
    events: Iterable[Mapping[str, object]], *, start: int, end: int
) -> list[dict[str, object]]:
    """Select timestamped asset events using an inclusive deterministic window."""
    if start > end:
        raise ValueError("start must be <= end")
    selected: list[dict[str, object]] = []
    for event in events:
        timestamp = event.get("timestamp")
        if isinstance(timestamp, int) and start <= timestamp <= end:
            selected.append(dict(event))
    return selected
