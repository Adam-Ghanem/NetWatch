from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


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
) -> dict[str, object]:
    del flows, devices, limits
    raise NotImplementedError("Flow topology aggregation is not implemented yet.")
