from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TypedDict


class DeviceEvidence(TypedDict):
    name: str
    type: str
    manufacturer: str
    confidence: str
    source: str


class TopologyNode(TypedDict):
    ip_address: str
    ip_version: int
    is_private: bool
    packets: int
    bytes: int
    sent_packets: int
    sent_bytes: int
    received_packets: int
    received_bytes: int
    conversation_count: int
    services: list[str]
    protocols: list[str]
    device: DeviceEvidence | None


class TopologyEdge(TypedDict):
    source: str
    target: str
    packets: int
    bytes: int
    source_to_target_packets: int
    source_to_target_bytes: int
    target_to_source_packets: int
    target_to_source_bytes: int
    flow_count: int
    flow_ids: list[str]
    services: list[str]
    protocols: list[str]


class TopologyResult(TypedDict):
    payload_retained: bool
    input_flow_count: int
    processed_flow_count: int
    accepted_flow_count: int
    ignored_flow_count: int
    node_count: int
    edge_count: int
    truncated: bool
    nodes: list[TopologyNode]
    edges: list[TopologyEdge]


@dataclass(frozen=True)
class TopologyLimits:
    max_flows: int = 1000
    max_nodes: int = 500
    max_edges: int = 1000
    max_flow_ids_per_edge: int = 25


def build_flow_topology(
    flows: Iterable[dict[str, object]],
    *,
    devices: Iterable[dict[str, object]] = (),
    limits: TopologyLimits | None = None,
) -> TopologyResult:
    del flows, devices, limits
    raise NotImplementedError("Flow topology aggregation is not implemented yet.")
