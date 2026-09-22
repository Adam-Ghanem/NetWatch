from __future__ import annotations

from collections.abc import Iterable
from typing import TypedDict

MAX_FLOW_HISTORY_FLOWS = 10_000

# Zeek conn.log history markers are case-sensitive by direction. Uppercase markers
# describe the originator and lowercase markers describe the responder.
_CAPTURE_GAP_MARKERS = frozenset("gG")
_PARTIAL_ANALYSIS_MARKERS = frozenset("xX")
_BAD_CHECKSUM_MARKERS = frozenset("cC")
_INCONSISTENT_MARKERS = frozenset("iIqQ")


class FlowHistoryQualitySummary(TypedDict):
    flow_count: int
    history_flow_count: int
    history_coverage_percent: float
    invalid_history_flow_count: int
    invalid_history_percent: float
    missing_history_flow_count: int
    missing_history_percent: float
    degraded_history_flow_count: int
    degraded_history_percent: float
    capture_gap_flow_count: int
    capture_gap_percent: float
    partial_analysis_flow_count: int
    partial_analysis_percent: float
    bad_checksum_flow_count: int
    bad_checksum_percent: float
    retransmission_flow_count: int
    retransmission_percent: float
    originator_retransmission_flow_count: int
    originator_retransmission_percent: float
    responder_retransmission_flow_count: int
    responder_retransmission_percent: float
    bidirectional_retransmission_flow_count: int
    bidirectional_retransmission_percent: float
    inconsistent_flow_count: int
    inconsistent_percent: float
    direction_flipped_flow_count: int
    direction_flipped_percent: float
    reset_flow_count: int
    reset_percent: float
    originator_reset_flow_count: int
    originator_reset_percent: float
    responder_reset_flow_count: int
    responder_reset_percent: float
    bidirectional_reset_flow_count: int
    bidirectional_reset_percent: float
    zero_window_flow_count: int
    zero_window_percent: float
    originator_zero_window_flow_count: int
    originator_zero_window_percent: float
    responder_zero_window_flow_count: int
    responder_zero_window_percent: float
    bidirectional_zero_window_flow_count: int
    bidirectional_zero_window_percent: float
    truncated: bool


def _percent(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(part * 100 / total, 2)


def _markers(history: str, candidates: frozenset[str]) -> bool:
    return any(marker in candidates for marker in history)


def flow_history_quality_summary(
    flows: Iterable[dict[str, object]], *, flow_limit: int = MAX_FLOW_HISTORY_FLOWS
) -> FlowHistoryQualitySummary:
    """Summarize bounded connection-history integrity signals without payload inspection.

    This helper consumes normalized ``history`` metadata compatible with Zeek-style
    connection history. It treats missing history separately from malformed present
    values and reports quality-degrading evidence such as content gaps, partial
    analysis, bad checksums, retransmissions, inconsistent/multi-flag packets, and
    zero-window receiver pressure. Retransmission, reset, and zero-window evidence is
    partitioned by Zeek's originator/responder direction so operators can identify
    which side emitted the transport signal without exposing endpoint identities.
    Resets and direction flips are transport/provenance context rather than degradation
    by themselves because both can occur during normal connection handling. Per-signal
    rates use all observed flows as the denominator so dashboards can compare them
    directly with history coverage and overall degradation rates.

    The result is descriptive evidence, not an intrusion verdict. Endpoint identities
    and packet payloads are never inspected.
    """
    if isinstance(flow_limit, bool) or not 1 <= flow_limit <= MAX_FLOW_HISTORY_FLOWS:
        raise ValueError(f"flow_limit must be between 1 and {MAX_FLOW_HISTORY_FLOWS}")

    total = valid = invalid = missing = degraded = 0
    capture_gap = partial = bad_checksum = inconsistent = 0
    retransmission = originator_retransmission = responder_retransmission = 0
    bidirectional_retransmission = 0
    direction_flipped = 0
    reset = originator_reset = responder_reset = bidirectional_reset = 0
    zero_window = 0
    originator_zero_window = 0
    responder_zero_window = 0
    bidirectional_zero_window = 0
    truncated = False

    for index, flow in enumerate(flows):
        if index >= flow_limit:
            truncated = True
            break
        total += 1

        if "history" not in flow or flow.get("history") is None:
            missing += 1
            continue

        value = flow.get("history")
        if not isinstance(value, str) or not value.strip():
            invalid += 1
            continue

        history = value.strip()
        valid += 1
        has_capture_gap = _markers(history, _CAPTURE_GAP_MARKERS)
        has_partial = _markers(history, _PARTIAL_ANALYSIS_MARKERS)
        has_bad_checksum = _markers(history, _BAD_CHECKSUM_MARKERS)
        has_originator_retransmission = "T" in history
        has_responder_retransmission = "t" in history
        has_retransmission = has_originator_retransmission or has_responder_retransmission
        has_inconsistent = _markers(history, _INCONSISTENT_MARKERS)
        has_direction_flip = "^" in history
        has_originator_reset = "R" in history
        has_responder_reset = "r" in history
        has_reset = has_originator_reset or has_responder_reset
        has_originator_zero_window = "W" in history
        has_responder_zero_window = "w" in history
        has_zero_window = has_originator_zero_window or has_responder_zero_window

        capture_gap += int(has_capture_gap)
        partial += int(has_partial)
        bad_checksum += int(has_bad_checksum)
        retransmission += int(has_retransmission)
        originator_retransmission += int(has_originator_retransmission)
        responder_retransmission += int(has_responder_retransmission)
        bidirectional_retransmission += int(
            has_originator_retransmission and has_responder_retransmission
        )
        inconsistent += int(has_inconsistent)
        direction_flipped += int(has_direction_flip)
        reset += int(has_reset)
        originator_reset += int(has_originator_reset)
        responder_reset += int(has_responder_reset)
        bidirectional_reset += int(has_originator_reset and has_responder_reset)
        zero_window += int(has_zero_window)
        originator_zero_window += int(has_originator_zero_window)
        responder_zero_window += int(has_responder_zero_window)
        bidirectional_zero_window += int(has_originator_zero_window and has_responder_zero_window)
        degraded += int(
            has_capture_gap
            or has_partial
            or has_bad_checksum
            or has_retransmission
            or has_inconsistent
            or has_zero_window
        )

    return {
        "flow_count": total,
        "history_flow_count": valid,
        "history_coverage_percent": _percent(valid, total),
        "invalid_history_flow_count": invalid,
        "invalid_history_percent": _percent(invalid, total),
        "missing_history_flow_count": missing,
        "missing_history_percent": _percent(missing, total),
        "degraded_history_flow_count": degraded,
        "degraded_history_percent": _percent(degraded, total),
        "capture_gap_flow_count": capture_gap,
        "capture_gap_percent": _percent(capture_gap, total),
        "partial_analysis_flow_count": partial,
        "partial_analysis_percent": _percent(partial, total),
        "bad_checksum_flow_count": bad_checksum,
        "bad_checksum_percent": _percent(bad_checksum, total),
        "retransmission_flow_count": retransmission,
        "retransmission_percent": _percent(retransmission, total),
        "originator_retransmission_flow_count": originator_retransmission,
        "originator_retransmission_percent": _percent(originator_retransmission, total),
        "responder_retransmission_flow_count": responder_retransmission,
        "responder_retransmission_percent": _percent(responder_retransmission, total),
        "bidirectional_retransmission_flow_count": bidirectional_retransmission,
        "bidirectional_retransmission_percent": _percent(bidirectional_retransmission, total),
        "inconsistent_flow_count": inconsistent,
        "inconsistent_percent": _percent(inconsistent, total),
        "direction_flipped_flow_count": direction_flipped,
        "direction_flipped_percent": _percent(direction_flipped, total),
        "reset_flow_count": reset,
        "reset_percent": _percent(reset, total),
        "originator_reset_flow_count": originator_reset,
        "originator_reset_percent": _percent(originator_reset, total),
        "responder_reset_flow_count": responder_reset,
        "responder_reset_percent": _percent(responder_reset, total),
        "bidirectional_reset_flow_count": bidirectional_reset,
        "bidirectional_reset_percent": _percent(bidirectional_reset, total),
        "zero_window_flow_count": zero_window,
        "zero_window_percent": _percent(zero_window, total),
        "originator_zero_window_flow_count": originator_zero_window,
        "originator_zero_window_percent": _percent(originator_zero_window, total),
        "responder_zero_window_flow_count": responder_zero_window,
        "responder_zero_window_percent": _percent(responder_zero_window, total),
        "bidirectional_zero_window_flow_count": bidirectional_zero_window,
        "bidirectional_zero_window_percent": _percent(bidirectional_zero_window, total),
        "truncated": truncated,
    }
