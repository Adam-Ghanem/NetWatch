from __future__ import annotations

import csv
import io
import json
from collections.abc import Iterable

SCHEMA = "netwatch.flow-report.v1"
CSV_FIELDS = (
    "flow_id",
    "protocol",
    "service",
    "originator_ip",
    "originator_port",
    "responder_ip",
    "responder_port",
    "packets",
    "bytes",
    "originator_packets",
    "originator_bytes",
    "responder_packets",
    "responder_bytes",
    "first_seen",
    "last_seen",
    "duration_ms",
    "tcp_state",
)


def _int(value: object) -> int:
    try:
        return max(0, int(str(value or 0)))
    except (TypeError, ValueError):
        return 0


def _endpoint(flow: dict[str, object], role: str) -> tuple[str, int | None]:
    endpoint = flow.get(role)
    if not isinstance(endpoint, dict):
        return "-", None
    ip_address = str(endpoint.get("ip") or "-")
    port = _int(endpoint.get("port")) or None
    return ip_address, port


def _safe_row(flow: dict[str, object]) -> dict[str, object]:
    originator_ip, originator_port = _endpoint(flow, "originator")
    responder_ip, responder_port = _endpoint(flow, "responder")
    return {
        "flow_id": str(flow.get("flow_id") or ""),
        "protocol": str(flow.get("protocol") or "Unknown"),
        "service": str(flow.get("service") or "-"),
        "originator_ip": originator_ip,
        "originator_port": originator_port,
        "responder_ip": responder_ip,
        "responder_port": responder_port,
        "packets": _int(flow.get("packets")),
        "bytes": _int(flow.get("bytes")),
        "originator_packets": _int(flow.get("originator_packets")),
        "originator_bytes": _int(flow.get("originator_bytes")),
        "responder_packets": _int(flow.get("responder_packets")),
        "responder_bytes": _int(flow.get("responder_bytes")),
        "first_seen": str(flow.get("first_seen") or ""),
        "last_seen": str(flow.get("last_seen") or ""),
        "duration_ms": _int(flow.get("duration_ms")),
        "tcp_state": str(flow.get("tcp_state") or flow.get("state") or "-"),
    }


def _bounded_rows(
    flows: Iterable[dict[str, object]],
    *,
    limit: int,
) -> list[dict[str, object]]:
    if limit < 1 or limit > 1000:
        raise ValueError("Flow export limit must be between 1 and 1000.")

    rows: list[dict[str, object]] = []
    for flow in flows:
        rows.append(_safe_row(flow))
        if len(rows) >= limit:
            break
    return rows


def export_flows_json(
    flows: Iterable[dict[str, object]],
    *,
    limit: int = 100,
) -> str:
    """Serialize bounded canonical flow metadata as a versioned JSON report."""
    rows = _bounded_rows(flows, limit=limit)
    return json.dumps(
        {
            "schema": SCHEMA,
            "flow_count": len(rows),
            "payload_retained": False,
            "flows": rows,
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def export_flows_csv(
    flows: Iterable[dict[str, object]],
    *,
    limit: int = 100,
) -> str:
    """Serialize bounded canonical flow metadata as stable flat CSV."""
    rows = _bounded_rows(flows, limit=limit)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(
        output,
        fieldnames=CSV_FIELDS,
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()
