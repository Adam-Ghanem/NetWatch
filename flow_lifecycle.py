from __future__ import annotations

from collections.abc import Iterable
from typing import TypedDict

MAX_FLOW_LIFECYCLE_FLOWS = 10_000


class FlowLifecycleSummary(TypedDict):
    flow_count: int
    tcp_flow_count: int
    tcp_percent: float
    established_flow_count: int
    established_percent: float
    graceful_close_flow_count: int
    graceful_close_percent: float
    reset_close_flow_count: int
    reset_close_percent: float
    incomplete_handshake_flow_count: int
    incomplete_handshake_percent: float
    midstream_flow_count: int
    midstream_percent: float
    missing_history_flow_count: int
    missing_history_percent: float
    invalid_history_flow_count: int
    invalid_history_percent: float
    truncated: bool


def _percent(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(part * 100 / total, 2)


def flow_lifecycle_summary(
    flows: Iterable[dict[str, object]], *, flow_limit: int = MAX_FLOW_LIFECYCLE_FLOWS
) -> FlowLifecycleSummary:
    """Summarize TCP lifecycle evidence from bounded Zeek-style flow metadata.

    The helper is intentionally descriptive rather than diagnostic. It reports whether
    observed TCP history contains evidence for the opening three-way handshake, a
    bidirectional FIN close, a reset, or traffic first observed after the SYN. Capture
    position and packet loss can make a healthy connection look incomplete, so none of
    these categories is an intrusion verdict.

    Percentages for TCP lifecycle categories use observed TCP flows as their denominator;
    missing/invalid-history percentages use all observed flows. Payloads and endpoint
    identities are never inspected.
    """
    if isinstance(flow_limit, bool) or not 1 <= flow_limit <= MAX_FLOW_LIFECYCLE_FLOWS:
        raise ValueError(f"flow_limit must be between 1 and {MAX_FLOW_LIFECYCLE_FLOWS}")

    total = tcp = established = graceful = reset = incomplete = midstream = 0
    missing = invalid = 0
    truncated = False

    for index, flow in enumerate(flows):
        if index >= flow_limit:
            truncated = True
            break
        total += 1

        proto = flow.get("proto")
        if not isinstance(proto, str) or proto.strip().lower() != "tcp":
            continue
        tcp += 1

        if "history" not in flow or flow.get("history") is None:
            missing += 1
            continue
        value = flow.get("history")
        if not isinstance(value, str) or not value.strip():
            invalid += 1
            continue

        history = value.strip()
        has_syn = "S" in history
        has_syn_ack = "h" in history
        has_originator_ack = "A" in history
        has_established = has_syn and has_syn_ack and has_originator_ack
        has_graceful_close = "F" in history and "f" in history
        has_reset = "R" in history or "r" in history
        has_payload_or_ack = any(marker in history for marker in "DdAa")
        has_midstream = not has_syn and has_payload_or_ack
        has_incomplete_handshake = has_syn and not has_established

        established += int(has_established)
        graceful += int(has_graceful_close)
        reset += int(has_reset)
        incomplete += int(has_incomplete_handshake)
        midstream += int(has_midstream)

    return {
        "flow_count": total,
        "tcp_flow_count": tcp,
        "tcp_percent": _percent(tcp, total),
        "established_flow_count": established,
        "established_percent": _percent(established, tcp),
        "graceful_close_flow_count": graceful,
        "graceful_close_percent": _percent(graceful, tcp),
        "reset_close_flow_count": reset,
        "reset_close_percent": _percent(reset, tcp),
        "incomplete_handshake_flow_count": incomplete,
        "incomplete_handshake_percent": _percent(incomplete, tcp),
        "midstream_flow_count": midstream,
        "midstream_percent": _percent(midstream, tcp),
        "missing_history_flow_count": missing,
        "missing_history_percent": _percent(missing, total),
        "invalid_history_flow_count": invalid,
        "invalid_history_percent": _percent(invalid, total),
        "truncated": truncated,
    }
