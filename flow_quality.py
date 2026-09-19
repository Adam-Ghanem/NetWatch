from __future__ import annotations

from collections.abc import Iterable
from typing import TypedDict

MAX_FLOW_QUALITY_FLOWS = 10_000


class FlowQualitySummary(TypedDict):
    flow_count: int
    directional_flow_count: int
    directional_coverage_percent: float
    service_flow_count: int
    service_coverage_percent: float
    duration_flow_count: int
    duration_coverage_percent: float
    state_flow_count: int
    state_coverage_percent: float
    complete_flow_count: int
    complete_flow_percent: float
    truncated: bool


def _present(flow: dict[str, object], key: str) -> bool:
    value = flow.get(key)
    return value is not None and str(value).strip().lower() not in {"", "-", "unknown"}


def _percent(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(part * 100 / total, 2)


def flow_quality_summary(
    flows: Iterable[dict[str, object]], *, flow_limit: int = MAX_FLOW_QUALITY_FLOWS
) -> FlowQualitySummary:
    """Measure completeness of normalized flow metadata without inspecting payloads.

    A flow has directional metadata when all originator/responder packet and byte
    counters are present, even when their legitimate value is zero. Service,
    duration, and state coverage are tracked independently. ``complete`` means
    all four metadata groups are available for the same flow.
    """
    if isinstance(flow_limit, bool) or not 1 <= flow_limit <= MAX_FLOW_QUALITY_FLOWS:
        raise ValueError(f"flow_limit must be between 1 and {MAX_FLOW_QUALITY_FLOWS}")

    total = directional = service = duration = state = complete = 0
    truncated = False
    directional_keys = (
        "originator_packets",
        "originator_bytes",
        "responder_packets",
        "responder_bytes",
    )

    for index, flow in enumerate(flows):
        if index >= flow_limit:
            truncated = True
            break
        total += 1
        has_directional = all(key in flow and flow.get(key) is not None for key in directional_keys)
        has_service = _present(flow, "service")
        has_duration = _present(flow, "duration")
        has_state = _present(flow, "state")
        directional += int(has_directional)
        service += int(has_service)
        duration += int(has_duration)
        state += int(has_state)
        complete += int(has_directional and has_service and has_duration and has_state)

    return {
        "flow_count": total,
        "directional_flow_count": directional,
        "directional_coverage_percent": _percent(directional, total),
        "service_flow_count": service,
        "service_coverage_percent": _percent(service, total),
        "duration_flow_count": duration,
        "duration_coverage_percent": _percent(duration, total),
        "state_flow_count": state,
        "state_coverage_percent": _percent(state, total),
        "complete_flow_count": complete,
        "complete_flow_percent": _percent(complete, total),
        "truncated": truncated,
    }
