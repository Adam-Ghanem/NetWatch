# fmt: off
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TypedDict

MAX_TCP_PAYLOAD_RECORDS = 10_000


class TcpPayloadEvidenceSummary(TypedDict):
    record_count: int
    tcp_record_count: int
    payload_segment_count: int
    payload_segment_percent: float
    payload_bytes: int
    originator_payload_bytes: int
    responder_payload_bytes: int
    payload_flow_count: int
    bidirectional_payload_flow_count: int
    unidirectional_payload_flow_count: int
    largest_payload_flow_bytes: int
    largest_payload_flow_percent: float
    metadata_missing_record_count: int
    truncated: bool
    payload_retained: bool


class _FlowPayloadEvidence(TypedDict):
    originator: tuple[str, int]
    responder: tuple[str, int]
    originator_bytes: int
    responder_bytes: int


def _percent(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(part * 100 / total, 2)


def _nonnegative_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _endpoint(record: Mapping[str, object], prefix: str) -> tuple[str, int] | None:
    address = str(record.get(f"{prefix}_ip") or "").strip()
    port = _nonnegative_int(record.get(f"{prefix}_port"))
    if not address or port is None or port > 65_535:
        return None
    return address, port


def _validate_record_limit(record_limit: int) -> None:
    if isinstance(record_limit, bool) or not 1 <= record_limit <= MAX_TCP_PAYLOAD_RECORDS:
        raise ValueError(f"record_limit must be between 1 and {MAX_TCP_PAYLOAD_RECORDS}")


def tcp_payload_evidence_summary(
    records: Iterable[Mapping[str, object]],
    *,
    record_limit: int = MAX_TCP_PAYLOAD_RECORDS,
) -> TcpPayloadEvidenceSummary:
    """Summarize bounded TCP data-plane evidence without retaining payload content.

    NetWatch's PCAP/PCAPNG sequence extractor already records TCP segment length while
    discarding payload bytes. This summary turns that metadata into analyst-friendly
    evidence about how much application data was observed, whether data moved in one
    or both directions, and whether one flow dominates the observed TCP payload.
    Missing segment-length metadata is reported explicitly; Ethernet frame length is
    never treated as TCP payload.
    """
    _validate_record_limit(record_limit)

    total = tcp = payload_segments = payload_bytes = missing = 0
    truncated = False
    flows: dict[tuple[tuple[str, int], tuple[str, int]], _FlowPayloadEvidence] = {}

    for index, record in enumerate(records):
        if index >= record_limit:
            truncated = True
            break
        total += 1
        if str(record.get("protocol") or "").strip().upper() != "TCP":
            continue
        tcp += 1

        segment_length = _nonnegative_int(record.get("tcp_segment_length"))
        source = _endpoint(record, "source")
        destination = _endpoint(record, "destination")
        if segment_length is None or source is None or destination is None:
            missing += 1
            continue
        if segment_length == 0:
            continue

        payload_segments += 1
        payload_bytes += segment_length
        key = (source, destination) if source <= destination else (destination, source)
        flow = flows.setdefault(
            key,
            {
                "originator": source,
                "responder": destination,
                "originator_bytes": 0,
                "responder_bytes": 0,
            },
        )
        if source == flow["originator"]:
            flow["originator_bytes"] += segment_length
        else:
            flow["responder_bytes"] += segment_length

    bidirectional = sum(
        1
        for flow in flows.values()
        if flow["originator_bytes"] > 0 and flow["responder_bytes"] > 0
    )
    unidirectional = len(flows) - bidirectional
    originator_bytes = sum(flow["originator_bytes"] for flow in flows.values())
    responder_bytes = sum(flow["responder_bytes"] for flow in flows.values())
    flow_payload_bytes = [
        flow["originator_bytes"] + flow["responder_bytes"] for flow in flows.values()
    ]
    largest_flow_bytes = max(flow_payload_bytes, default=0)

    return {
        "record_count": total,
        "tcp_record_count": tcp,
        "payload_segment_count": payload_segments,
        "payload_segment_percent": _percent(payload_segments, tcp),
        "payload_bytes": payload_bytes,
        "originator_payload_bytes": originator_bytes,
        "responder_payload_bytes": responder_bytes,
        "payload_flow_count": len(flows),
        "bidirectional_payload_flow_count": bidirectional,
        "unidirectional_payload_flow_count": unidirectional,
        "largest_payload_flow_bytes": largest_flow_bytes,
        "largest_payload_flow_percent": _percent(largest_flow_bytes, payload_bytes),
        "metadata_missing_record_count": missing,
        "truncated": truncated,
        "payload_retained": False,
    }
# fmt: on
