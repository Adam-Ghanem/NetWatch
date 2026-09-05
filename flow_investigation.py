from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TypedDict

from flow_analysis import summarize_conversations
from flow_anomaly import FlowAnomalyPolicy, analyze_flow_anomalies
from flow_correlation import CorrelationPolicy, correlate_flow_events
from flow_query import FlowQuery, query_flows
from flow_topology import TopologyLimits, TopologyResult, build_flow_topology


class InvestigationResult(TypedDict):
    payload_retained: bool
    matched_flow_count: int
    event_count: int
    flows: list[dict[str, object]]
    conversations: dict[str, object]
    topology: TopologyResult
    anomalies: list[dict[str, object]]


@dataclass(frozen=True)
class InvestigationLimits:
    flow_limit: int = 100
    conversation_limit: int = 100
    endpoint_limit: int = 100
    max_events: int = 10_000
    max_events_per_flow: int = 100
    topology_nodes: int = 250
    topology_edges: int = 500

    def validate(self) -> None:
        for label, value in (
            ("flow_limit", self.flow_limit),
            ("conversation_limit", self.conversation_limit),
            ("endpoint_limit", self.endpoint_limit),
        ):
            if not 1 <= value <= 1000:
                raise ValueError(f"{label} must be between 1 and 1000.")
        if not 1 <= self.max_events <= 50_000:
            raise ValueError("max_events must be between 1 and 50000.")
        if not 1 <= self.max_events_per_flow <= 1000:
            raise ValueError("max_events_per_flow must be between 1 and 1000.")
        if not 1 <= self.topology_nodes <= 1000:
            raise ValueError("topology_nodes must be between 1 and 1000.")
        if not 1 <= self.topology_edges <= 5000:
            raise ValueError("topology_edges must be between 1 and 5000.")


def build_flow_investigation(
    flows: Iterable[dict[str, object]],
    *,
    query: FlowQuery | None = None,
    events: Iterable[dict[str, object]] = (),
    devices: Iterable[dict[str, object]] = (),
    limits: InvestigationLimits | None = None,
) -> InvestigationResult:
    """Build one bounded, metadata-only analyst investigation snapshot.

    Querying happens first so conversations, protocol-event correlation, topology,
    and explainable anomaly findings are scoped to the same analyst selection. Only
    allowlisted protocol metadata reaches correlated flows; raw payloads are never
    copied or returned. Anomalies expose deterministic thresholds and bounded evidence
    rather than opaque risk scores.
    """
    selected = limits or InvestigationLimits()
    selected.validate()

    requested_query = query or FlowQuery(limit=selected.flow_limit)
    effective_query = FlowQuery(
        ip_address=requested_query.ip_address,
        protocol=requested_query.protocol,
        service=requested_query.service,
        state=requested_query.state,
        min_bytes=requested_query.min_bytes,
        sort_by=requested_query.sort_by,
        limit=min(requested_query.limit, selected.flow_limit),
    )
    matched = query_flows(flows, effective_query)

    correlation = correlate_flow_events(
        matched,
        events,
        policy=CorrelationPolicy(
            max_flows=selected.flow_limit,
            max_events=selected.max_events,
            max_events_per_flow=selected.max_events_per_flow,
        ),
    )
    enriched_flows = correlation["flows"]

    conversations = summarize_conversations(
        enriched_flows,
        conversation_limit=selected.conversation_limit,
        endpoint_limit=selected.endpoint_limit,
    )
    topology = build_flow_topology(
        enriched_flows,
        devices=devices,
        limits=TopologyLimits(
            max_flows=selected.flow_limit,
            max_nodes=selected.topology_nodes,
            max_edges=selected.topology_edges,
        ),
    )
    anomalies = analyze_flow_anomalies(
        enriched_flows,
        policy=FlowAnomalyPolicy(max_flows=selected.flow_limit),
    )

    return {
        "payload_retained": False,
        "matched_flow_count": len(enriched_flows),
        "event_count": correlation["event_count"],
        "flows": enriched_flows,
        "conversations": conversations,
        "topology": topology,
        "anomalies": anomalies,
    }
