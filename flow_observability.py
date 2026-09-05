"""Bounded observability records for canonical NetWatch flow metadata."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

MAX_OBSERVABILITY_RECORDS = 1_000
_MAX_PROTOCOL_EVENT_TYPES = 8
_ALLOWED_PROTOCOL_EVENT_TYPES = {"dns", "http", "tls"}


class FlowObservabilityError(ValueError):
    """Raised when observability controls are invalid."""


def _text(value: object) -> str:
    return "" if value is None else str(value).strip()


def _count(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if not isinstance(value, (int, float, str, bytes, bytearray)):
        return 0
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def _endpoint(flow: dict[str, object], key: str) -> tuple[str, int]:
    value = flow.get(key)
    if not isinstance(value, dict):
        return "", 0
    address = _text(value.get("ip"))
    return address, min(_count(value.get("port")), 65_535)


def _address_family(source: str, destination: str) -> str:
    for address in (source, destination):
        if not address:
            continue
        try:
            version = ip_address(address).version
        except ValueError:
            continue
        return "ipv6" if version == 6 else "ipv4"
    return ""


def _protocol_event_types(flow: dict[str, object]) -> list[str]:
    events = flow.get("protocol_events")
    if not isinstance(events, list):
        return []

    event_types: list[str] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        event_type = _text(event.get("event_type")).lower()
        if event_type not in _ALLOWED_PROTOCOL_EVENT_TYPES or event_type in event_types:
            continue
        event_types.append(event_type)
        if len(event_types) >= _MAX_PROTOCOL_EVENT_TYPES:
            break
    return event_types


def _record(flow: dict[str, object]) -> dict[str, Any]:
    source, source_port = _endpoint(flow, "originator")
    destination, destination_port = _endpoint(flow, "responder")
    protocol_event_types = _protocol_event_types(flow)
    attributes: dict[str, Any] = {
        "netwatch.flow.id": _text(flow.get("flow_id")),
        "network.community_id": _text(flow.get("community_id")),
        "source.address": source,
        "source.port": source_port,
        "destination.address": destination,
        "destination.port": destination_port,
        "network.transport": _text(flow.get("protocol")).lower(),
        "network.type": _address_family(source, destination),
        "network.protocol.name": _text(flow.get("service")).lower(),
        "netwatch.flow.state": _text(flow.get("state", flow.get("tcp_state"))),
        "netwatch.flow.packets": _count(flow.get("packets")),
        "netwatch.flow.bytes": _count(flow.get("bytes")),
        "netwatch.flow.originator.packets": _count(flow.get("originator_packets")),
        "netwatch.flow.originator.bytes": _count(flow.get("originator_bytes")),
        "netwatch.flow.responder.packets": _count(flow.get("responder_packets")),
        "netwatch.flow.responder.bytes": _count(flow.get("responder_bytes")),
        "netwatch.flow.duration_ms": _count(flow.get("duration_ms")),
        "netwatch.flow.protocol_event_count": min(_count(flow.get("protocol_event_count")), 1_000),
        "netwatch.flow.protocol_event_types": protocol_event_types,
    }
    return {"schema": "netwatch.flow.v1", "attributes": attributes}


def build_flow_observability_records(
    flows: list[dict[str, object]], *, limit: int = 100
) -> list[dict[str, Any]]:
    """Return an explicit metadata allowlist suitable for observability export.

    Protocol correlation is intentionally reduced to event counts/types. DNS names,
    TLS server names, HTTP hosts and other potentially sensitive L7 values are never
    copied into this integration record.
    """

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise FlowObservabilityError("limit must be an integer between 1 and 1000")
    if not 1 <= limit <= MAX_OBSERVABILITY_RECORDS:
        raise FlowObservabilityError("limit must be between 1 and 1000")

    return [_record(flow) for flow in flows[:limit] if isinstance(flow, dict)]
