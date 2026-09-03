from __future__ import annotations

from dataclasses import dataclass

from flow_analysis import summarize_conversations
from flow_display_filter import filter_flows
from flow_query import FlowQuery, FlowSort, query_flows


@dataclass(frozen=True)
class TrafficFlowControls:
    """Bounded, metadata-only analyst controls for captured flow summaries."""

    display_filter: str = ""
    ip_address: str = ""
    protocol: str = ""
    service: str = ""
    state: str = ""
    min_bytes: int = 0
    sort_by: FlowSort = "bytes"
    limit: int = 100

    def as_query(self) -> FlowQuery:
        return FlowQuery(
            ip_address=self.ip_address,
            protocol=self.protocol,
            service=self.service,
            state=self.state,
            min_bytes=self.min_bytes,
            sort_by=self.sort_by,
            limit=self.limit,
        )

    def is_active(self) -> bool:
        return bool(
            self.display_filter.strip()
            or self.ip_address.strip()
            or self.protocol.strip()
            or self.service.strip()
            or self.state.strip()
            or self.min_bytes
            or self.sort_by != "bytes"
            or self.limit != 100
        )


def _flow_rows(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def apply_traffic_flow_controls(
    capture_result: dict[str, object],
    controls: TrafficFlowControls,
) -> dict[str, object]:
    """Apply safe display filtering plus bounded FlowQuery ranking to capture flows.

    When controls are active, conversation and endpoint pivots are rebuilt from the
    selected flow set so an analyst never sees stale unfiltered conversation rows
    beside filtered flow results. The compatibility path remains unchanged when no
    controls are active.
    """

    result = dict(capture_result)
    query = controls.as_query()
    query.validate()

    if not controls.is_active():
        return result

    flows = _flow_rows(capture_result.get("flows"))
    display_filtered = filter_flows(flows, controls.display_filter, limit=1000)
    selected = query_flows(display_filtered, query)
    conversation_summary = summarize_conversations(
        selected,
        conversation_limit=1000,
        endpoint_limit=1000,
    )

    result["flows"] = selected
    result["flow_count"] = len(selected)
    result["conversations"] = conversation_summary["conversations"]
    result["conversation_count"] = conversation_summary["conversation_count"]
    result["endpoints"] = conversation_summary["endpoints"]
    result["endpoint_count"] = conversation_summary["endpoint_count"]
    result["conversation_totals"] = conversation_summary["totals"]
    result["flow_analysis"] = {
        "applied": True,
        "input_flow_count": len(flows),
        "matched_flow_count": len(selected),
        "display_filter": controls.display_filter.strip(),
        "sort_by": controls.sort_by,
        "limit": controls.limit,
        "conversation_pivots_recomputed": True,
    }
    return result
