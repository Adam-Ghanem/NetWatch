from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal, TypedDict

_SUPPORTED_EVENT_FIELDS: dict[str, tuple[str, ...]] = {
    "dns": ("answers", "qtype", "query", "rcode"),
    "tls": ("alpn", "cipher", "server_name", "version"),
    "http": ("content_type", "host", "method", "status_code"),
}
_MAX_TEXT_LENGTH = 512
_MAX_DNS_ANSWERS = 20


class CorrelationResult(TypedDict):
    flow_count: int
    event_count: int
    payload_retained: Literal[False]
    flows: list[dict[str, object]]


@dataclass(frozen=True)
class CorrelationPolicy:
    """Bounds for metadata-only flow/protocol event correlation."""

    max_flows: int = 5_000
    max_events: int = 50_000
    max_events_per_flow: int = 100

    def validate(self) -> None:
        if self.max_flows < 1 or self.max_flows > 50_000:
            raise ValueError("Flow correlation limit must be between 1 and 50000.")
        if self.max_events < 1 or self.max_events > 50_000:
            raise ValueError("Protocol event limit must be between 1 and 50000.")
        if self.max_events_per_flow < 1 or self.max_events_per_flow > 1_000:
            raise ValueError("Per-flow protocol event limit must be between 1 and 1000.")


def _bounded_text(value: object) -> str:
    return str(value or "").strip()[:_MAX_TEXT_LENGTH]


def _safe_scalar(value: object) -> object:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    return _bounded_text(value)


def _safe_metadata(event_type: str, metadata: object) -> dict[str, object]:
    if not isinstance(metadata, dict):
        return {}

    allowed = _SUPPORTED_EVENT_FIELDS[event_type]
    cleaned: dict[str, object] = {}
    for key in allowed:
        if key not in metadata:
            continue
        value = metadata[key]
        if event_type == "dns" and key == "answers":
            if isinstance(value, (list, tuple)):
                cleaned[key] = [_bounded_text(item) for item in value[:_MAX_DNS_ANSWERS]]
            continue
        cleaned[key] = _safe_scalar(value)
    return cleaned


def correlate_flow_events(
    flows: Iterable[dict[str, object]],
    events: Iterable[dict[str, object]],
    *,
    policy: CorrelationPolicy | None = None,
) -> CorrelationResult:
    """Attach bounded DNS/TLS/HTTP metadata events to canonical flow records.

    Correlation is performed only with existing ``flow_id`` values. Event fields are
    copied through explicit protocol-specific allowlists so payloads, HTTP paths,
    cookies, authorization headers, and other raw content are never retained here.
    Unknown event types and events that do not map to a known flow are ignored.
    """
    selected = policy or CorrelationPolicy()
    selected.validate()

    flow_records = [dict(flow) for flow in flows]
    if len(flow_records) > selected.max_flows:
        raise ValueError(f"Flow correlation accepts at most {selected.max_flows} flows.")

    event_records = [dict(event) for event in events]
    if len(event_records) > selected.max_events:
        raise ValueError(f"Flow correlation accepts at most {selected.max_events} protocol events.")

    by_id: dict[str, dict[str, object]] = {}
    ordered_flows: list[dict[str, object]] = []
    for flow in flow_records:
        flow_id = _bounded_text(flow.get("flow_id"))
        enriched = dict(flow)
        enriched["protocol_events"] = []
        enriched["protocol_event_count"] = 0
        ordered_flows.append(enriched)
        if flow_id:
            by_id.setdefault(flow_id, enriched)

    accepted_events = 0
    for event in event_records:
        flow_id = _bounded_text(event.get("flow_id"))
        event_type = _bounded_text(event.get("event_type")).lower()
        if not flow_id or event_type not in _SUPPORTED_EVENT_FIELDS:
            continue
        matched_flow = by_id.get(flow_id)
        if matched_flow is None:
            continue

        protocol_events = matched_flow["protocol_events"]
        if not isinstance(protocol_events, list):
            continue
        if len(protocol_events) >= selected.max_events_per_flow:
            continue

        protocol_events.append(
            {
                "event_type": event_type,
                "timestamp": _bounded_text(event.get("timestamp")),
                "metadata": _safe_metadata(event_type, event.get("metadata")),
            }
        )
        matched_flow["protocol_event_count"] = len(protocol_events)
        accepted_events += 1

    return {
        "flow_count": len(ordered_flows),
        "event_count": accepted_events,
        "payload_retained": False,
        "flows": ordered_flows,
    }
