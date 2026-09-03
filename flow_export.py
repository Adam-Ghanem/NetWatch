from __future__ import annotations

import json
from collections.abc import Iterable

import pandas as pd

from export_utils import safe_csv_bytes

FLOW_EXPORT_MAX_ROWS = 1000

_SCALAR_FIELDS = (
    "flow_id",
    "protocol",
    "service",
    "tcp_state",
    "packets",
    "bytes",
    "a_to_b_packets",
    "a_to_b_bytes",
    "b_to_a_packets",
    "b_to_a_bytes",
    "originator_packets",
    "originator_bytes",
    "responder_packets",
    "responder_bytes",
    "first_seen",
    "last_seen",
    "duration_ms",
)
_ENDPOINT_FIELDS = ("endpoint_a", "endpoint_b", "originator", "responder")
_CSV_COLUMNS = (
    "flow_id",
    "protocol",
    "service",
    "tcp_state",
    "endpoint_a_ip",
    "endpoint_a_port",
    "endpoint_b_ip",
    "endpoint_b_port",
    "originator_ip",
    "originator_port",
    "responder_ip",
    "responder_port",
    "packets",
    "bytes",
    "a_to_b_packets",
    "a_to_b_bytes",
    "b_to_a_packets",
    "b_to_a_bytes",
    "originator_packets",
    "originator_bytes",
    "responder_packets",
    "responder_bytes",
    "first_seen",
    "last_seen",
    "duration_ms",
)


def _validate_limit(limit: int) -> None:
    if limit < 1 or limit > FLOW_EXPORT_MAX_ROWS:
        raise ValueError(f"Flow export limit must be between 1 and {FLOW_EXPORT_MAX_ROWS}.")


def _endpoint(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {"ip": "", "port": None}
    ip_address = str(value.get("ip") or "").strip()
    port_value = value.get("port")
    if port_value in {None, ""}:
        port: int | None = None
    else:
        try:
            port = int(str(port_value))
        except (TypeError, ValueError):
            port = None
    return {"ip": ip_address, "port": port}


def _metadata(flow: dict[str, object]) -> dict[str, object]:
    exported = {field: flow.get(field) for field in _SCALAR_FIELDS}
    for field in _ENDPOINT_FIELDS:
        exported[field] = _endpoint(flow.get(field))
    return exported


def _bounded_metadata(
    flows: Iterable[dict[str, object]],
    *,
    limit: int,
) -> list[dict[str, object]]:
    _validate_limit(limit)
    rows: list[dict[str, object]] = []
    for flow in flows:
        rows.append(_metadata(flow))
        if len(rows) >= limit:
            break
    return rows


def export_flows_json(
    flows: Iterable[dict[str, object]],
    *,
    limit: int = 100,
) -> bytes:
    """Serialize canonical flow metadata without exporting packet payload fields."""
    rows = _bounded_metadata(flows, limit=limit)
    payload = {
        "count": len(rows),
        "payload_retained": False,
        "flows": rows,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def export_flows_ndjson(
    flows: Iterable[dict[str, object]],
    *,
    limit: int = 100,
) -> bytes:
    """Serialize canonical flow metadata as bounded newline-delimited JSON records."""
    rows = _bounded_metadata(flows, limit=limit)
    lines = [
        json.dumps(
            {"event_type": "flow", "payload_retained": False, **row},
            separators=(",", ":"),
            sort_keys=True,
        )
        for row in rows
    ]
    if not lines:
        return b""
    return ("\n".join(lines) + "\n").encode("utf-8")


def export_flows_csv(
    flows: Iterable[dict[str, object]],
    *,
    limit: int = 100,
) -> bytes:
    """Flatten canonical flow metadata into formula-safe UTF-8 CSV."""
    rows = _bounded_metadata(flows, limit=limit)
    flattened: list[dict[str, object]] = []
    for row in rows:
        item = {field: row.get(field) for field in _SCALAR_FIELDS}
        for field in _ENDPOINT_FIELDS:
            endpoint = _endpoint(row.get(field))
            item[f"{field}_ip"] = endpoint["ip"]
            item[f"{field}_port"] = endpoint["port"]
        flattened.append(item)
    return safe_csv_bytes(pd.DataFrame(flattened, columns=_CSV_COLUMNS))
