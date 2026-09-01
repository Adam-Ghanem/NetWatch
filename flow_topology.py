from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sized
from dataclasses import dataclass, field
from itertools import islice
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

    def validate(self) -> None:
        _validate_limit("max_flows", self.max_flows, 5000)
        _validate_limit("max_nodes", self.max_nodes, 1000)
        _validate_limit("max_edges", self.max_edges, 5000)
        _validate_limit("max_flow_ids_per_edge", self.max_flow_ids_per_edge, 100)


@dataclass
class _NodeState:
    ip_address: str
    sent_packets: int = 0
    sent_bytes: int = 0
    received_packets: int = 0
    received_bytes: int = 0
    conversation_count: int = 0
    services: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)


@dataclass
class _EdgeState:
    source: str
    target: str
    source_to_target_packets: int = 0
    source_to_target_bytes: int = 0
    target_to_source_packets: int = 0
    target_to_source_bytes: int = 0
    flow_count: int = 0
    flow_ids: list[str] = field(default_factory=list)
    services: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)

    @property
    def packets(self) -> int:
        return self.source_to_target_packets + self.target_to_source_packets

    @property
    def bytes(self) -> int:
        return self.source_to_target_bytes + self.target_to_source_bytes


def _validate_limit(name: str, value: int, maximum: int) -> None:
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}.")


def _safe_int(value: object) -> int:
    try:
        return max(0, int(str(value or 0)))
    except (TypeError, ValueError):
        return 0


def _normalize_token(value: object, *, uppercase: bool = False) -> str:
    token = str(value or "").strip()
    if not token or token == "-":
        return ""
    return token.upper() if uppercase else token.lower()


def _endpoint_ip(flow: dict[str, object], role: str) -> str | None:
    endpoint = flow.get(role)
    if not isinstance(endpoint, dict):
        return None
    value = endpoint.get("ip")
    if value is None:
        return None
    candidate = str(value).strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _device_index(devices: Iterable[dict[str, object]]) -> dict[str, DeviceEvidence]:
    index: dict[str, DeviceEvidence] = {}
    for device in devices:
        value = device.get("ip_address")
        if value is None:
            continue
        try:
            address = str(ipaddress.ip_address(str(value).strip()))
        except ValueError:
            continue
        index[address] = {
            "name": str(device.get("device_name") or "").strip(),
            "type": str(device.get("device_type") or "").strip(),
            "manufacturer": str(device.get("manufacturer") or "").strip(),
            "confidence": str(device.get("identity_confidence") or "").strip(),
            "source": str(device.get("identity_source") or "").strip(),
        }
    return index


def _bounded_flows(
    flows: Iterable[dict[str, object]], max_flows: int
) -> tuple[list[dict[str, object]], int, bool]:
    if isinstance(flows, Sized):
        input_count = len(flows)
        selected = list(islice(iter(flows), max_flows))
        return selected, input_count, input_count > max_flows

    observed = list(islice(iter(flows), max_flows + 1))
    truncated = len(observed) > max_flows
    return observed[:max_flows], len(observed), truncated


def _touch_node(
    nodes: dict[str, _NodeState],
    ip_address: str,
    *,
    sent_packets: int,
    sent_bytes: int,
    received_packets: int,
    received_bytes: int,
    service: str,
    protocol: str,
) -> None:
    node = nodes.setdefault(ip_address, _NodeState(ip_address=ip_address))
    node.sent_packets += sent_packets
    node.sent_bytes += sent_bytes
    node.received_packets += received_packets
    node.received_bytes += received_bytes
    node.conversation_count += 1
    if service:
        node.services.add(service)
    if protocol:
        node.protocols.add(protocol)


def _node_payload(
    node: _NodeState, device_map: dict[str, DeviceEvidence]
) -> TopologyNode:
    address = ipaddress.ip_address(node.ip_address)
    packets = node.sent_packets + node.received_packets
    bytes_count = node.sent_bytes + node.received_bytes
    return {
        "ip_address": node.ip_address,
        "ip_version": address.version,
        "is_private": address.is_private,
        "packets": packets,
        "bytes": bytes_count,
        "sent_packets": node.sent_packets,
        "sent_bytes": node.sent_bytes,
        "received_packets": node.received_packets,
        "received_bytes": node.received_bytes,
        "conversation_count": node.conversation_count,
        "services": sorted(node.services),
        "protocols": sorted(node.protocols),
        "device": device_map.get(node.ip_address),
    }


def _edge_payload(edge: _EdgeState) -> TopologyEdge:
    return {
        "source": edge.source,
        "target": edge.target,
        "packets": edge.packets,
        "bytes": edge.bytes,
        "source_to_target_packets": edge.source_to_target_packets,
        "source_to_target_bytes": edge.source_to_target_bytes,
        "target_to_source_packets": edge.target_to_source_packets,
        "target_to_source_bytes": edge.target_to_source_bytes,
        "flow_count": edge.flow_count,
        "flow_ids": edge.flow_ids.copy(),
        "services": sorted(edge.services),
        "protocols": sorted(edge.protocols),
    }


def build_flow_topology(
    flows: Iterable[dict[str, object]],
    *,
    devices: Iterable[dict[str, object]] = (),
    limits: TopologyLimits | None = None,
) -> TopologyResult:
    policy = limits or TopologyLimits()
    policy.validate()

    selected_flows, input_count, flow_truncated = _bounded_flows(
        flows, policy.max_flows
    )
    device_map = _device_index(devices)
    nodes: dict[str, _NodeState] = {}
    edges: dict[tuple[str, str], _EdgeState] = {}
    ignored_flow_count = 0

    for flow in selected_flows:
        source = _endpoint_ip(flow, "originator")
        target = _endpoint_ip(flow, "responder")
        if source is None or target is None:
            ignored_flow_count += 1
            continue

        source_packets = _safe_int(flow.get("originator_packets"))
        source_bytes = _safe_int(flow.get("originator_bytes"))
        target_packets = _safe_int(flow.get("responder_packets"))
        target_bytes = _safe_int(flow.get("responder_bytes"))
        protocol = _normalize_token(flow.get("protocol"), uppercase=True)
        service = _normalize_token(flow.get("service"))

        _touch_node(
            nodes,
            source,
            sent_packets=source_packets,
            sent_bytes=source_bytes,
            received_packets=target_packets,
            received_bytes=target_bytes,
            service=service,
            protocol=protocol,
        )
        _touch_node(
            nodes,
            target,
            sent_packets=target_packets,
            sent_bytes=target_bytes,
            received_packets=source_packets,
            received_bytes=source_bytes,
            service=service,
            protocol=protocol,
        )

        edge = edges.setdefault((source, target), _EdgeState(source, target))
        edge.source_to_target_packets += source_packets
        edge.source_to_target_bytes += source_bytes
        edge.target_to_source_packets += target_packets
        edge.target_to_source_bytes += target_bytes
        edge.flow_count += 1
        flow_id = str(flow.get("flow_id") or "").strip()
        if (
            flow_id
            and flow_id not in edge.flow_ids
            and len(edge.flow_ids) < policy.max_flow_ids_per_edge
        ):
            edge.flow_ids.append(flow_id)
        if service:
            edge.services.add(service)
        if protocol:
            edge.protocols.add(protocol)

    ranked_nodes = sorted(
        nodes.values(),
        key=lambda node: (
            -(node.sent_bytes + node.received_bytes),
            -(node.sent_packets + node.received_packets),
            node.ip_address,
        ),
    )
    selected_nodes = ranked_nodes[: policy.max_nodes]
    selected_addresses = {node.ip_address for node in selected_nodes}

    ranked_edges = sorted(
        (
            edge
            for edge in edges.values()
            if edge.source in selected_addresses and edge.target in selected_addresses
        ),
        key=lambda edge: (-edge.bytes, -edge.packets, edge.source, edge.target),
    )
    selected_edges = ranked_edges[: policy.max_edges]

    accepted_flow_count = len(selected_flows) - ignored_flow_count
    topology_truncated = (
        flow_truncated
        or len(ranked_nodes) > policy.max_nodes
        or len(ranked_edges) > policy.max_edges
        or len(ranked_edges) < len(edges)
    )
    return {
        "payload_retained": False,
        "input_flow_count": input_count,
        "processed_flow_count": len(selected_flows),
        "accepted_flow_count": accepted_flow_count,
        "ignored_flow_count": ignored_flow_count,
        "node_count": len(selected_nodes),
        "edge_count": len(selected_edges),
        "truncated": topology_truncated,
        "nodes": [_node_payload(node, device_map) for node in selected_nodes],
        "edges": [_edge_payload(edge) for edge in selected_edges],
    }
