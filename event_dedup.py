from __future__ import annotations

from collections.abc import Iterable, Mapping
import hashlib
import json


def event_fingerprint(event: Mapping[str, object]) -> str:
    """Create a stable identifier for semantically identical events."""
    normalized = {str(k): event[k] for k in sorted(event) if k not in {"timestamp", "seen_at"}}
    payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def deduplicate_events(events: Iterable[Mapping[str, object]]) -> list[dict[str, object]]:
    """Keep the first occurrence of each event fingerprint."""
    seen: set[str] = set()
    result: list[dict[str, object]] = []
    for event in events:
        key = event_fingerprint(event)
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(event))
    return result
