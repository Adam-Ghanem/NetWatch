from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import TypedDict

MAX_TCP_COMPLETENESS_FLOWS = 1000


class TcpCompletenessSummary(TypedDict):
    flow_count: int
    tcp_flow_count: int
    opening_complete_flow_count: int
    opening_complete_percent: float
    data_flow_count: int
    data_percent: float
    closing_observed_flow_count: int
    closing_observed_percent: float
    complete_with_data_flow_count: int
    complete_with_data_percent: float
    complete_without_data_flow_count: int
    complete_without_data_percent: float
    incomplete_flow_count: int
    incomplete_percent: float
    history_truncated_flow_count: int
    history_truncated_percent: float
    missing_history_flow_count: int
    missing_history_percent: float
    truncated: bool


def _percent(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(part * 100 / total, 2)


def tcp_completeness_summary(
    flows: Iterable[Mapping[str, object]],
    *,
    flow_limit: int = MAX_TCP_COMPLETENESS_FLOWS,
) -> TcpCompletenessSummary:
    """Summarize bounded TCP conversation completeness from NetWatch metadata.

    The model mirrors the useful operator concept behind Wireshark's TCP conversation
    completeness without copying its representation: opening evidence requires SYN,
    SYN-ACK, and the originator ACK; closing evidence requires either a FIN or RST in
    either direction. Data is reported independently. A complete conversation therefore
    has opening and closing evidence, with or without observed data.

    Results describe capture evidence, not endpoint health or security posture. A capture
    can begin late, end early, or lose packets. Raw payloads and endpoint identities are
    never inspected or retained.
    """
    if (
        isinstance(flow_limit, bool)
        or not 1 <= flow_limit <= MAX_TCP_COMPLETENESS_FLOWS
    ):
        raise ValueError(f"flow_limit must be between 1 and {MAX_TCP_COMPLETENESS_FLOWS}")

    total = tcp = opening = data = closing = complete_data = complete_no_data = 0
    incomplete = history_truncated = missing_history = 0
    truncated = False

    for index, flow in enumerate(flows):
        if index >= flow_limit:
            truncated = True
            break
        total += 1

        protocol = flow.get("protocol")
        if not isinstance(protocol, str) or protocol.strip().upper() != "TCP":
            continue
        tcp += 1

        raw_history = flow.get("tcp_history")
        if not isinstance(raw_history, list):
            missing_history += 1
            incomplete += 1
            continue

        events = {event for event in raw_history if isinstance(event, str)}
        has_opening = {">S", "<SA", ">A"}.issubset(events)
        has_data = bool(events.intersection({">D", "<D"}))
        has_closing = bool(events.intersection({">F", "<F", ">R", "<R"}))
        is_complete = has_opening and has_closing

        opening += int(has_opening)
        data += int(has_data)
        closing += int(has_closing)
        complete_data += int(is_complete and has_data)
        complete_no_data += int(is_complete and not has_data)
        incomplete += int(not is_complete)
        history_truncated += int(flow.get("tcp_history_truncated") is True)

    return {
        "flow_count": total,
        "tcp_flow_count": tcp,
        "opening_complete_flow_count": opening,
        "opening_complete_percent": _percent(opening, tcp),
        "data_flow_count": data,
        "data_percent": _percent(data, tcp),
        "closing_observed_flow_count": closing,
        "closing_observed_percent": _percent(closing, tcp),
        "complete_with_data_flow_count": complete_data,
        "complete_with_data_percent": _percent(complete_data, tcp),
        "complete_without_data_flow_count": complete_no_data,
        "complete_without_data_percent": _percent(complete_no_data, tcp),
        "incomplete_flow_count": incomplete,
        "incomplete_percent": _percent(incomplete, tcp),
        "history_truncated_flow_count": history_truncated,
        "history_truncated_percent": _percent(history_truncated, tcp),
        "missing_history_flow_count": missing_history,
        "missing_history_percent": _percent(missing_history, tcp),
        "truncated": truncated,
    }
