from __future__ import annotations

import math
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
    invalid_directional_flow_count: int
    invalid_directional_percent: float
    missing_directional_flow_count: int
    missing_directional_percent: float
    invalid_service_flow_count: int
    invalid_service_percent: float
    missing_service_flow_count: int
    missing_service_percent: float
    invalid_duration_flow_count: int
    invalid_duration_percent: float
    missing_duration_flow_count: int
    missing_duration_percent: float
    invalid_state_flow_count: int
    invalid_state_percent: float
    missing_state_flow_count: int
    missing_state_percent: float
    capture_loss_flow_count: int
    capture_loss_percent: float
    invalid_capture_loss_flow_count: int
    invalid_capture_loss_percent: float
    capture_loss_bytes: int
    truncated: bool


def _text_present(flow: dict[str, object], key: str) -> bool:
    value = flow.get(key)
    return isinstance(value, str) and value.strip().lower() not in {"", "-", "unknown"}


def _nonnegative_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _valid_duration(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(float(value)) and value >= 0


def _percent(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return round(part * 100 / total, 2)


def flow_quality_summary(
    flows: Iterable[dict[str, object]], *, flow_limit: int = MAX_FLOW_QUALITY_FLOWS
) -> FlowQualitySummary:
    """Measure validity, completeness, and capture integrity of flow metadata.

    Each metadata group is partitioned into valid, invalid, or missing. Directional
    counters are invalid when only part of the four-field group is present, because
    partial directional telemetry cannot safely support bidirectional analytics.
    Directional counters must be non-negative integers, while duration must be a
    finite non-negative number. Service and state must be meaningful strings.
    ``missed_bytes`` is treated as an optional capture-integrity signal: a positive
    value marks a flow whose content had gaps, while malformed present values are
    reported separately. ``complete`` means all four core metadata groups are valid
    for the same flow; capture loss is intentionally reported independently.
    Payloads and endpoint identities are never inspected.
    """
    if isinstance(flow_limit, bool) or not 1 <= flow_limit <= MAX_FLOW_QUALITY_FLOWS:
        raise ValueError(f"flow_limit must be between 1 and {MAX_FLOW_QUALITY_FLOWS}")

    total = directional = service = duration = state = complete = 0
    invalid_directional = invalid_service = invalid_duration = invalid_state = 0
    missing_directional = missing_service = missing_duration = missing_state = 0
    capture_loss_flows = invalid_capture_loss = capture_loss_bytes = 0
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

        directional_values = [flow.get(key) for key in directional_keys]
        directional_field_count = sum(
            key in flow and flow.get(key) is not None for key in directional_keys
        )
        directional_present = directional_field_count == len(directional_keys)
        has_directional = directional_present and all(
            _nonnegative_integer(value) for value in directional_values
        )
        directional_missing = directional_field_count == 0

        service_present = "service" in flow and flow.get("service") is not None
        has_service = _text_present(flow, "service")
        duration_present = "duration" in flow and flow.get("duration") is not None
        has_duration = duration_present and _valid_duration(flow.get("duration"))
        state_present = "state" in flow and flow.get("state") is not None
        has_state = _text_present(flow, "state")

        missed_bytes_present = "missed_bytes" in flow and flow.get("missed_bytes") is not None
        missed_bytes = flow.get("missed_bytes")
        valid_missed_bytes = missed_bytes_present and _nonnegative_integer(missed_bytes)
        if valid_missed_bytes and isinstance(missed_bytes, int):
            capture_loss_flows += int(missed_bytes > 0)
            capture_loss_bytes += missed_bytes
        elif missed_bytes_present:
            invalid_capture_loss += 1

        directional += int(has_directional)
        service += int(has_service)
        duration += int(has_duration)
        state += int(has_state)
        invalid_directional += int(not directional_missing and not has_directional)
        missing_directional += int(directional_missing)
        invalid_service += int(service_present and not has_service)
        missing_service += int(not service_present)
        invalid_duration += int(duration_present and not has_duration)
        missing_duration += int(not duration_present)
        invalid_state += int(state_present and not has_state)
        missing_state += int(not state_present)
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
        "invalid_directional_flow_count": invalid_directional,
        "invalid_directional_percent": _percent(invalid_directional, total),
        "missing_directional_flow_count": missing_directional,
        "missing_directional_percent": _percent(missing_directional, total),
        "invalid_service_flow_count": invalid_service,
        "invalid_service_percent": _percent(invalid_service, total),
        "missing_service_flow_count": missing_service,
        "missing_service_percent": _percent(missing_service, total),
        "invalid_duration_flow_count": invalid_duration,
        "invalid_duration_percent": _percent(invalid_duration, total),
        "missing_duration_flow_count": missing_duration,
        "missing_duration_percent": _percent(missing_duration, total),
        "invalid_state_flow_count": invalid_state,
        "invalid_state_percent": _percent(invalid_state, total),
        "missing_state_flow_count": missing_state,
        "missing_state_percent": _percent(missing_state, total),
        "capture_loss_flow_count": capture_loss_flows,
        "capture_loss_percent": _percent(capture_loss_flows, total),
        "invalid_capture_loss_flow_count": invalid_capture_loss,
        "invalid_capture_loss_percent": _percent(invalid_capture_loss, total),
        "capture_loss_bytes": capture_loss_bytes,
        "truncated": truncated,
    }
