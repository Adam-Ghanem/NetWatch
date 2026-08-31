from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

FlowSort = Literal["bytes", "packets", "duration", "recent"]


@dataclass(frozen=True)
class FlowQuery:
    """Bounded analyst filters for metadata-only flow summaries."""

    ip_address: str = ""
    protocol: str = ""
    service: str = ""
    state: str = ""
    min_bytes: int = 0
    sort_by: FlowSort = "bytes"
    limit: int = 100

    def validate(self) -> None:
        if self.min_bytes < 0:
            raise ValueError("Minimum flow bytes cannot be negative.")
        if self.limit < 1 or self.limit > 1000:
            raise ValueError("Flow query limit must be between 1 and 1000.")
        if self.sort_by not in {"bytes", "packets", "duration", "recent"}:
            raise ValueError("Unsupported flow sort order.")


def _int(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError):
        return 0


def _text(value: object) -> str:
    return str(value or "").strip().lower()


def _endpoint_ips(flow: dict[str, object]) -> set[str]:
    values: set[str] = set()
    for key in ("originator", "responder", "endpoint_a", "endpoint_b"):
        endpoint = flow.get(key)
        if isinstance(endpoint, dict):
            ip_address = str(endpoint.get("ip") or "").strip()
            if ip_address:
                values.add(ip_address)
    return values


def _matches(flow: dict[str, object], query: FlowQuery) -> bool:
    if query.ip_address and query.ip_address not in _endpoint_ips(flow):
        return False
    if query.protocol and _text(flow.get("protocol")) != _text(query.protocol):
        return False
    if query.service and _text(flow.get("service")) != _text(query.service):
        return False
    if query.state and _text(flow.get("state")) != _text(query.state):
        return False
    if _int(flow.get("bytes")) < query.min_bytes:
        return False
    return True


def _sort_key(flow: dict[str, object], sort_by: FlowSort) -> tuple[object, ...]:
    if sort_by == "packets":
        return (-_int(flow.get("packets")), -_int(flow.get("bytes")))
    if sort_by == "duration":
        return (-_int(flow.get("duration_ms")), -_int(flow.get("bytes")))
    if sort_by == "recent":
        return (_text(flow.get("last_seen")), _text(flow.get("flow_id")))
    return (-_int(flow.get("bytes")), -_int(flow.get("packets")))


def query_flows(
    flows: Iterable[dict[str, object]],
    query: FlowQuery | None = None,
) -> list[dict[str, object]]:
    """Filter and rank flow summaries without inspecting or retaining payloads."""
    selected = query or FlowQuery()
    selected.validate()
    matches = [dict(flow) for flow in flows if _matches(flow, selected)]
    matches.sort(
        key=lambda flow: _sort_key(flow, selected.sort_by),
        reverse=selected.sort_by == "recent",
    )
    return matches[: selected.limit]
