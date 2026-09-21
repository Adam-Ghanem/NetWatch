from __future__ import annotations

from collections.abc import Iterable
from typing import TypedDict

MAX_FLOW_HISTORY_FLOWS = 10_000

# Zeek conn.log history markers are case-sensitive by direction, but quality
# semantics are the same for the upper/lowercase variants.
_CAPTURE_GAP_MARKERS = frozenset("gG")
_PARTIAL_ANALYSIS_MARKERS = frozenset("xX")
_BAD_CHECKSUM_MARKERS = frozenset("cC")
_RETRANSMISSION_MARKERS = frozenset("tT")
_INCONSISTENT_MARKERS = frozenset("iIqQ")
_ZERO_WINDOW_MARKERS = frozenset("wW")


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
    inconsistent_flow_count: int
    inconsistent_percent: float
    zero_window_flow_count: int
    zero_window_percent: float
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
    zero-window receiver pressure. Per-signal rates use all observed flows as the
    denominator so dashboards can compare them directly with history coverage and
    overall degradation rates.

    The result is descriptive evidence, not an intrusion verdict. Endpoint identities
    and packet payloads are never inspected.
    """
    if isinstance(flow_limit, bool) or not 1 <= flow_limit <= MAX_FLOW_HISTORY_FLOWS:
        raise ValueError(f"flow_limit must be between 1 and {MAX_FLOW_HISTORY_FLOWS}")

    total = valid = invalid = missing = degraded = 0
    capture_gap = partial = bad_checksum = retransmission = inconsistent = 0
    zero_window = 0
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
        has_retransmission = _markers(history, _RETRANSMISSION_MARKERS)
        has_inconsistent = _markers(history, _INCONSISTENT_MARKERS)
        has_zero_window = _markers(history, _ZERO_WINDOW_MARKERS)

        capture_gap += int(has_capture_gap)
        partial += int(has_partial)
        bad_checksum += int(has_bad_checksum)
        retransmission += int(has_retransmission)
        inconsistent += int(has_inconsistent)
        zero_window += int(has_zero_window)
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
        "inconsistent_flow_count": inconsistent,
        "inconsistent_percent": _percent(inconsistent, total),
        "zero_window_flow_count": zero_window,
        "zero_window_percent": _percent(zero_window, total),
        "truncated": truncated,
    }
