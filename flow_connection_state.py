from __future__ import annotations

from collections.abc import Iterable
from typing import TypedDict

MAX_CONNECTION_STATE_FLOWS = 10_000

# Zeek conn.log TCP connection states. Keep outcome groups explicit so a new or
# malformed state is surfaced as unknown rather than silently misclassified.
_RECOGNIZED_STATES = frozenset(
    {
        "S0",
        "S1",
        "SF",
        "REJ",
        "S2",
        "S3",
        "RSTO",
        "RSTR",
        "RSTOS0",
        "RSTRH",
        "SH",
        "SHR",
        "OTH",
    }
)
_ESTABLISHED_STATES = frozenset({"S1", "SF", "S2", "S3", "RSTO", "RSTR"})
_RESET_STATES = frozenset({"RSTO", "RSTR", "RSTOS0", "RSTRH"})
_HALF_CLOSE_STATES = frozenset({"S2", "S3"})
_HALF_OPEN_STATES = frozenset({"SH", "SHR"})


class ConnectionStateSummary(TypedDict):
    flow_count: int
    tcp_flow_count: int
    tcp_percent: float
    state_flow_count: int
    state_coverage_percent: float
    normal_close_flow_count: int
    normal_close_percent: float
    established_unterminated_flow_count: int
    established_unterminated_percent: float
    established_flow_count: int
    established_percent: float
    no_reply_flow_count: int
    no_reply_percent: float
    rejected_flow_count: int
    rejected_percent: float
    reset_flow_count: int
    reset_percent: float
    half_close_flow_count: int
    half_close_percent: float
    half_open_flow_count: int
    half_open_percent: float
    midstream_flow_count: int
    midstream_percent: float
    missing_state_flow_count: int
    missing_state_percent: float
    invalid_state_flow_count: int
    invalid_state_percent: float
    unknown_state_flow_count: int
    unknown_state_percent: float
    truncated: bool


def _percent(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(part * 100 / total, 2)


def connection_state_summary(
    flows: Iterable[dict[str, object]], *, flow_limit: int = MAX_CONNECTION_STATE_FLOWS
) -> ConnectionStateSummary:
    """Summarize bounded TCP outcomes from Zeek-style ``conn_state`` metadata.

    Connection states complement packet-history lifecycle evidence with Zeek's final
    interpretation of each observed TCP flow. The categories are descriptive operator
    telemetry, not security verdicts: no-reply, half-open, reset, and midstream states
    can all have benign causes such as filtering, application behavior, or capture
    position. Percentages for state outcomes use observed TCP flows as the denominator.

    Unknown non-empty states are reported separately so schema/version drift remains
    visible instead of being folded into a known outcome. Payloads and endpoint
    identities are never inspected.
    """
    if isinstance(flow_limit, bool) or not 1 <= flow_limit <= MAX_CONNECTION_STATE_FLOWS:
        raise ValueError(f"flow_limit must be between 1 and {MAX_CONNECTION_STATE_FLOWS}")

    total = tcp = state_count = 0
    normal = unterminated = established = no_reply = rejected = reset = 0
    half_close = half_open = midstream = missing = invalid = unknown = 0
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

        if "conn_state" not in flow or flow.get("conn_state") is None:
            missing += 1
            continue
        value = flow.get("conn_state")
        if not isinstance(value, str) or not value.strip():
            invalid += 1
            continue

        state = value.strip().upper()
        state_count += 1
        if state not in _RECOGNIZED_STATES:
            unknown += 1
            continue

        normal += int(state == "SF")
        unterminated += int(state == "S1")
        established += int(state in _ESTABLISHED_STATES)
        no_reply += int(state == "S0")
        rejected += int(state == "REJ")
        reset += int(state in _RESET_STATES)
        half_close += int(state in _HALF_CLOSE_STATES)
        half_open += int(state in _HALF_OPEN_STATES)
        midstream += int(state == "OTH")

    return {
        "flow_count": total,
        "tcp_flow_count": tcp,
        "tcp_percent": _percent(tcp, total),
        "state_flow_count": state_count,
        "state_coverage_percent": _percent(state_count, tcp),
        "normal_close_flow_count": normal,
        "normal_close_percent": _percent(normal, tcp),
        "established_unterminated_flow_count": unterminated,
        "established_unterminated_percent": _percent(unterminated, tcp),
        "established_flow_count": established,
        "established_percent": _percent(established, tcp),
        "no_reply_flow_count": no_reply,
        "no_reply_percent": _percent(no_reply, tcp),
        "rejected_flow_count": rejected,
        "rejected_percent": _percent(rejected, tcp),
        "reset_flow_count": reset,
        "reset_percent": _percent(reset, tcp),
        "half_close_flow_count": half_close,
        "half_close_percent": _percent(half_close, tcp),
        "half_open_flow_count": half_open,
        "half_open_percent": _percent(half_open, tcp),
        "midstream_flow_count": midstream,
        "midstream_percent": _percent(midstream, tcp),
        "missing_state_flow_count": missing,
        "missing_state_percent": _percent(missing, tcp),
        "invalid_state_flow_count": invalid,
        "invalid_state_percent": _percent(invalid, tcp),
        "unknown_state_flow_count": unknown,
        "unknown_state_percent": _percent(unknown, tcp),
        "truncated": truncated,
    }
