from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

MAX_PROTOCOL_HIERARCHY_FLOWS = 10_000
MAX_PROTOCOL_HIERARCHY_ROWS = 128


def _safe_nonnegative_int(value: object) -> int:
    try:
        return max(0, int(str(value or 0)))
    except (TypeError, ValueError):
        return 0


def _normalized_protocol(value: object) -> str:
    protocol = str(value or "unknown").strip().lower()
    return protocol[:32] or "unknown"


def _normalized_service(value: object) -> str:
    service = str(value or "-").strip().lower()
    if service in {"", "-", "unknown"}:
        return "unknown"
    return service[:64]


def protocol_hierarchy_summary(
    flows: Iterable[dict],
    *,
    flow_limit: int = MAX_PROTOCOL_HIERARCHY_FLOWS,
    row_limit: int = MAX_PROTOCOL_HIERARCHY_ROWS,
) -> dict[str, object]:
    """Build a bounded, metadata-only protocol hierarchy from normalized flows.

    The summary intentionally operates on existing flow metadata. It performs no
    capture or scanning and does not inspect or retain payload bytes. Transport
    protocols are parents and recognized application services are child rows.
    """
    if (
        isinstance(flow_limit, bool)
        or not 1 <= flow_limit <= MAX_PROTOCOL_HIERARCHY_FLOWS
    ):
        raise ValueError(f"flow_limit must be between 1 and {MAX_PROTOCOL_HIERARCHY_FLOWS}")
    if (
        isinstance(row_limit, bool)
        or not 1 <= row_limit <= MAX_PROTOCOL_HIERARCHY_ROWS
    ):
        raise ValueError(f"row_limit must be between 1 and {MAX_PROTOCOL_HIERARCHY_ROWS}")

    counters: dict[tuple[str, str | None], dict[str, int]] = defaultdict(
        lambda: {"flows": 0, "packets": 0, "bytes": 0}
    )
    total_flows = total_packets = total_bytes = 0
    truncated = False

    for index, flow in enumerate(flows):
        if index >= flow_limit:
            truncated = True
            break
        protocol = _normalized_protocol(flow.get("protocol"))
        service = _normalized_service(flow.get("service"))
        packets = _safe_nonnegative_int(flow.get("packets"))
        bytes_count = _safe_nonnegative_int(flow.get("bytes"))
        total_flows += 1
        total_packets += packets
        total_bytes += bytes_count
        for key in ((protocol, None), (protocol, service)):
            counters[key]["flows"] += 1
            counters[key]["packets"] += packets
            counters[key]["bytes"] += bytes_count

    rows: list[dict[str, object]] = []
    for (protocol, service), values in counters.items():
        rows.append(
            {
                "protocol": protocol,
                "service": service,
                "level": "transport" if service is None else "application",
                **values,
                "flow_percent": round(values["flows"] * 100 / total_flows, 2)
                if total_flows
                else 0.0,
                "packet_percent": round(values["packets"] * 100 / total_packets, 2)
                if total_packets
                else 0.0,
                "byte_percent": round(values["bytes"] * 100 / total_bytes, 2)
                if total_bytes
                else 0.0,
            }
        )
    rows.sort(
        key=lambda row: (
            -int(row["bytes"]),
            0 if row["level"] == "transport" else 1,
            str(row["protocol"]),
            str(row["service"] or ""),
        )
    )
    if len(rows) > row_limit:
        rows = rows[:row_limit]
        truncated = True

    return {
        "flow_count": total_flows,
        "packet_count": total_packets,
        "byte_count": total_bytes,
        "truncated": truncated,
        "privacy": {"payload_retained": False, "metadata_only": True},
        "rows": rows,
    }
