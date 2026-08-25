from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class TopologyNode:
    id: str
    label: str
    kind: str
    status: str = "unknown"
    confidence: str = "medium"

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class TopologyEdge:
    source: str
    target: str
    relation: str
    confidence: str = "medium"
    evidence: str = ""

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _clean(value: object, limit: int = 160) -> str:
    return " ".join(str(value or "").split())[:limit]


def build_topology(
    assets: Iterable[dict],
    neighbors: Iterable[dict] | None = None,
    *,
    gateway_ips: Iterable[str] | None = None,
) -> dict[str, list[dict[str, str]]]:
    """Build an evidence-backed local topology graph.

    This intentionally reports only relationships supported by local neighbor-table
    evidence or an explicitly configured gateway. It never infers L2 adjacency from
    an IP scan alone.
    """
    nodes: dict[str, TopologyNode] = {}
    edges: dict[tuple[str, str, str], TopologyEdge] = {}
    gateway_set = {str(value).strip() for value in (gateway_ips or ()) if str(value).strip()}

    for raw in assets:
        ip = _clean(raw.get("ip_address") or raw.get("IP Address"), 64)
        if not ip:
            continue
        label = _clean(raw.get("hostname") or raw.get("device_name") or ip, 120)
        kind = _clean(raw.get("device_type") or "host", 80).lower()
        if ip in gateway_set or "gateway" in kind or "router" in kind:
            kind = "gateway"
        nodes[ip] = TopologyNode(
            id=ip,
            label=label,
            kind=kind,
            status=_clean(raw.get("status") or "unknown", 32),
            confidence=_clean(raw.get("identity_confidence") or "medium", 32).lower(),
        )

    for raw in neighbors or ():
        ip = _clean(raw.get("ip_address") or raw.get("IP Address"), 64)
        gateway = _clean(raw.get("gateway_ip") or raw.get("gateway"), 64)
        interface = _clean(raw.get("interface"), 64)
        if ip and ip not in nodes:
            nodes[ip] = TopologyNode(id=ip, label=ip, kind="host")
        if gateway and gateway not in nodes:
            nodes[gateway] = TopologyNode(id=gateway, label=gateway, kind="gateway")
        if ip and gateway and ip != gateway:
            key = (ip, gateway, "gateway")
            edges[key] = TopologyEdge(
                source=ip,
                target=gateway,
                relation="gateway",
                confidence="high",
                evidence=f"neighbor-table{': ' + interface if interface else ''}",
            )

    return {
        "nodes": [node.as_dict() for node in nodes.values()],
        "edges": [edge.as_dict() for edge in edges.values()],
    }


def topology_changes(previous: dict, current: dict) -> dict[str, list[dict[str, str]]]:
    """Return deterministic node/edge additions and removals between snapshots."""
    prev_nodes = {str(item.get("id")): item for item in previous.get("nodes", [])}
    curr_nodes = {str(item.get("id")): item for item in current.get("nodes", [])}

    def edge_key(item: dict) -> tuple[str, str, str]:
        return (str(item.get("source")), str(item.get("target")), str(item.get("relation")))

    prev_edges = {edge_key(item): item for item in previous.get("edges", [])}
    curr_edges = {edge_key(item): item for item in current.get("edges", [])}
    return {
        "nodes_added": [curr_nodes[key] for key in sorted(curr_nodes.keys() - prev_nodes.keys())],
        "nodes_removed": [prev_nodes[key] for key in sorted(prev_nodes.keys() - curr_nodes.keys())],
        "edges_added": [curr_edges[key] for key in sorted(curr_edges.keys() - prev_edges.keys())],
        "edges_removed": [prev_edges[key] for key in sorted(prev_edges.keys() - curr_edges.keys())],
    }
