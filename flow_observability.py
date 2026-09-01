"""Bounded observability records for canonical NetWatch flow metadata."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

MAX_OBSERVABILITY_RECORDS = 1_000


class FlowObservabilityError(ValueError):
    """Raised when observability controls are invalid."""


def _text(value: object) -> str:
    return "" if value is None else str(value).strip()


def _count(value: object) -> int:
    if isinstance(value, bool):
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


def _record(flow: dict[str, object]) -> dict[str, Any]:
    source, source_port = _endpoint(flow, "originator")
    destination, destination_port = _endpoint(flow, "responder")
    attributes: dict[str, Any] = {
        "netwatch.flow.id": _text(flow.get("flow_id")),
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
    }
    return {"schema": "netwatch.flow.v1", "attributes": attributes}


def build_flow_observability_records(
    flows: list[dict[str, object]], *, limit: int = 100
) -> list[dict[str, Any]]:
    """Return an explicit metadata allowlist suitable for observability export."""

    if isinstance(limit, bool) or not isinstance(limit, int):
        raise FlowObservabilityError("limit must be an integer between 1 and 1000")
    if not 1 <= limit <= MAX_OBSERVABILITY_RECORDS:
        raise FlowObservabilityError("limit must be between 1 and 1000")

    return [_record(flow) for flow in flows[:limit] if isinstance(flow, dict)]
