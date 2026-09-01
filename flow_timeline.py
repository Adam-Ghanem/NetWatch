from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal, TypedDict

from flow_correlation import CorrelationPolicy, correlate_flow_events

_MAX_TEXT_LENGTH = 512


class TimelineResult(TypedDict):
    flow_count: int
    event_count: int
    entry_count: int
    payload_retained: Literal[False]
    entries: list[dict[str, object]]


@dataclass(frozen=True)
class TimelinePolicy:
    """Bounds for privacy-safe flow investigation timelines."""

    max_flows: int = 5_000
    max_events: int = 50_000
    max_entries: int = 10_000
    max_events_per_flow: int = 100

    def validate(self) -> None:
        if self.max_flows < 1 or self.max_flows > 50_000:
            raise ValueError("Timeline flow limit must be between 1 and 50000.")
        if self.max_events < 1 or self.max_events > 50_000:
            raise ValueError("Timeline event limit must be between 1 and 50000.")
        if self.max_entries < 1 or self.max_entries > 50_000:
            raise ValueError("Timeline entry limit must be between 1 and 50000.")
        if self.max_events_per_flow < 1 or self.max_events_per_flow > 1_000:
            raise ValueError("Timeline per-flow event limit must be between 1 and 1000.")


def _text(value: object) -> str:
    return str(value or "").strip()[:_MAX_TEXT_LENGTH]


def _counter(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return max(0, value)
    return 0


def _duration(value: object) -> int | float:
    if isinstance(value, bool):
        return 0
    if isinstance(value, (int, float)):
        return max(0, value)
    return 0


def _endpoint(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"ip": "", "port": 0}
    port = value.get("port")
    safe_port = port if isinstance(port, int) and not isinstance(port, bool) else 0
    return {
        "ip": _text(value.get("ip")),
        "port": safe_port if 0 <= safe_port <= 65_535 else 0,
    }


def _flow_entry(flow: dict[str, object]) -> dict[str, object]:
    state = _text(flow.get("state")) or _text(flow.get("tcp_state"))
    return {
        "timestamp": _text(flow.get("first_seen")),
        "flow_id": _text(flow.get("flow_id")),
        "event_type": "flow",
        "protocol": _text(flow.get("protocol")).lower(),
        "service": _text(flow.get("service")).lower(),
        "state": state,
        "originator": _endpoint(flow.get("originator")),
        "responder": _endpoint(flow.get("responder")),
        "packets": _counter(flow.get("packets")),
        "bytes": _counter(flow.get("bytes")),
        "originator_packets": _counter(flow.get("originator_packets")),
        "originator_bytes": _counter(flow.get("originator_bytes")),
        "responder_packets": _counter(flow.get("responder_packets")),
        "responder_bytes": _counter(flow.get("responder_bytes")),
        "duration_ms": _duration(flow.get("duration_ms")),
        "last_seen": _text(flow.get("last_seen")),
    }


def _protocol_entries(flow: dict[str, object]) -> list[dict[str, object]]:
    flow_id = _text(flow.get("flow_id"))
    raw_events = flow.get("protocol_events")
    if not isinstance(raw_events, list):
        return []

    entries: list[dict[str, object]] = []
    for event in raw_events:
        if not isinstance(event, dict):
            continue
        metadata = event.get("metadata")
        entries.append(
            {
                "timestamp": _text(event.get("timestamp")),
                "flow_id": flow_id,
                "event_type": _text(event.get("event_type")).lower(),
                "metadata": dict(metadata) if isinstance(metadata, dict) else {},
            }
        )
    return entries


def _timeline_sort_key(entry: dict[str, object]) -> tuple[bool, str, str, int]:
    timestamp = _text(entry.get("timestamp"))
    event_type = _text(entry.get("event_type"))
    return (
        not bool(timestamp),
        timestamp,
        _text(entry.get("flow_id")),
        0 if event_type == "flow" else 1,
    )


def build_flow_timeline(
    flows: Iterable[dict[str, object]],
    events: Iterable[dict[str, object]],
    *,
    policy: TimelinePolicy | None = None,
) -> TimelineResult:
    """Build one ordered, bounded timeline from flow and safe protocol metadata.

    Flow entries are rebuilt from an explicit field allowlist. DNS/TLS/HTTP entries
    come from the existing correlation allowlists. Raw payloads, HTTP paths,
    authorization data, cookies, and arbitrary metadata are never copied here.
    """

    selected = policy or TimelinePolicy()
    selected.validate()

    correlated = correlate_flow_events(
        flows,
        events,
        policy=CorrelationPolicy(
            max_flows=selected.max_flows,
            max_events=selected.max_events,
            max_events_per_flow=selected.max_events_per_flow,
        ),
    )

    entries: list[dict[str, object]] = []
    for flow in correlated["flows"]:
        entries.append(_flow_entry(flow))
        entries.extend(_protocol_entries(flow))

    entries.sort(key=_timeline_sort_key)
    bounded_entries = entries[: selected.max_entries]
    return {
        "flow_count": correlated["flow_count"],
        "event_count": correlated["event_count"],
        "entry_count": len(bounded_entries),
        "payload_retained": False,
        "entries": bounded_entries,
    }
