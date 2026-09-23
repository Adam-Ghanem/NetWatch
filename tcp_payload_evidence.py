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
    bidirectional_payload_flow_count: int
    unidirectional_payload_flow_count: int
    metadata_missing_record_count: int
    truncated: bool
    payload_retained: bool


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


def tcp_payload_evidence_summary(
    records: Iterable[Mapping[str, object]],
    *,
    record_limit: int = MAX_TCP_PAYLOAD_RECORDS,
) -> TcpPayloadEvidenceSummary:
    """Summarize bounded TCP data-plane evidence without retaining payload content.

    NetWatch's PCAP/PCAPNG sequence extractor already records TCP segment length while
    discarding payload bytes. This summary turns that metadata into analyst-friendly
    evidence about how much application data was observed and whether data moved in
    one or both directions. Missing segment-length metadata is reported explicitly;
    Ethernet frame length is never treated as TCP payload.
    """
    if isinstance(record_limit, bool) or not 1 <= record_limit <= MAX_TCP_PAYLOAD_RECORDS:
        raise ValueError(f"record_limit must be between 1 and {MAX_TCP_PAYLOAD_RECORDS}")

    total = tcp = payload_segments = payload_bytes = missing = 0
    truncated = False
    flows: dict[
        tuple[tuple[str, int], tuple[str, int]],
        dict[tuple[str, int], int],
    ] = {}

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
        left, right = sorted((source, destination))
        directions = flows.setdefault((left, right), {left: 0, right: 0})
        directions[source] = directions.get(source, 0) + segment_length

    bidirectional = sum(1 for values in flows.values() if all(value > 0 for value in values.values()))
    unidirectional = len(flows) - bidirectional

    originator_bytes = 0
    responder_bytes = 0
    for values in flows.values():
        ordered = list(values.values())
        if ordered:
            originator_bytes += ordered[0]
        if len(ordered) > 1:
            responder_bytes += ordered[1]

    return {
        "record_count": total,
        "tcp_record_count": tcp,
        "payload_segment_count": payload_segments,
        "payload_segment_percent": _percent(payload_segments, tcp),
        "payload_bytes": payload_bytes,
        "originator_payload_bytes": originator_bytes,
        "responder_payload_bytes": responder_bytes,
        "bidirectional_payload_flow_count": bidirectional,
        "unidirectional_payload_flow_count": unidirectional,
        "metadata_missing_record_count": missing,
        "truncated": truncated,
        "payload_retained": False,
    }
