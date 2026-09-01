from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class FlowAnomalyPolicy:
    """Safe, explainable thresholds for metadata-only flow anomaly signals."""

    high_fanout_threshold: int = 20
    reset_burst_threshold: int = 5
    byte_asymmetry_ratio: float = 20.0
    byte_asymmetry_min_bytes: int = 10_000
    max_flows: int = 5_000

    def validate(self) -> None:
        if self.high_fanout_threshold < 2:
            raise ValueError("Fan-out threshold must be at least 2.")
        if self.reset_burst_threshold < 2:
            raise ValueError("Reset-burst threshold must be at least 2.")
        if self.byte_asymmetry_ratio < 2.0:
            raise ValueError("Byte-asymmetry ratio must be at least 2.0.")
        if self.byte_asymmetry_min_bytes < 0:
            raise ValueError("Byte-asymmetry minimum bytes cannot be negative.")
        if self.max_flows < 1 or self.max_flows > 50_000:
            raise ValueError("Flow analysis bound must be between 1 and 50000.")


def _int(value: object) -> int:
    try:
        return max(0, int(str(value or 0)))
    except (TypeError, ValueError):
        return 0


def _ip(flow: dict[str, object], role: str) -> str:
    endpoint = flow.get(role)
    if not isinstance(endpoint, dict):
        return ""
    return str(endpoint.get("ip") or "").strip()


def _flow_id(flow: dict[str, object]) -> str:
    return str(flow.get("flow_id") or "").strip()


def _state(flow: dict[str, object]) -> str:
    return str(flow.get("tcp_state") or flow.get("state") or "").strip().lower()


def analyze_flow_anomalies(
    flows: Iterable[dict[str, object]],
    *,
    policy: FlowAnomalyPolicy | None = None,
) -> list[dict[str, object]]:
    """Flag unusual metadata patterns without labeling them malicious or reading payloads."""
    selected = policy or FlowAnomalyPolicy()
    selected.validate()
    records = [dict(flow) for flow in flows]
    if len(records) > selected.max_flows:
        raise ValueError(f"Flow anomaly analysis accepts at most {selected.max_flows} flows.")

    destinations: dict[str, set[str]] = defaultdict(set)
    fanout_flow_ids: dict[str, list[str]] = defaultdict(list)
    reset_flow_ids: dict[str, list[str]] = defaultdict(list)
    findings: list[dict[str, object]] = []

    for flow in records:
        source = _ip(flow, "originator")
        destination = _ip(flow, "responder")
        flow_id = _flow_id(flow)
        if source and destination:
            destinations[source].add(destination)
            if flow_id:
                fanout_flow_ids[source].append(flow_id)
        if source and _state(flow) == "reset" and flow_id:
            reset_flow_ids[source].append(flow_id)

        originator_bytes = _int(flow.get("originator_bytes"))
        responder_bytes = _int(flow.get("responder_bytes"))
        total_bytes = _int(flow.get("bytes")) or originator_bytes + responder_bytes
        smaller = min(originator_bytes, responder_bytes)
        larger = max(originator_bytes, responder_bytes)
        if total_bytes < selected.byte_asymmetry_min_bytes or larger == 0:
            continue
        ratio = float(larger) if smaller == 0 else larger / smaller
        if ratio >= selected.byte_asymmetry_ratio:
            findings.append(
                {
                    "signal": "byte_asymmetry",
                    "severity": "medium",
                    "entity": flow_id or source or destination or "unknown-flow",
                    "flow_ids": [flow_id] if flow_id else [],
                    "observed": round(ratio, 2),
                    "threshold": float(selected.byte_asymmetry_ratio),
                    "explanation": (
                        "Directional byte volume is highly asymmetric for a material flow; "
                        "validate whether the service normally has this traffic shape."
                    ),
                }
            )

    for source, unique_destinations in destinations.items():
        count = len(unique_destinations)
        if count >= selected.high_fanout_threshold:
            findings.append(
                {
                    "signal": "high_fanout",
                    "severity": "high",
                    "entity": source,
                    "flow_ids": sorted(set(fanout_flow_ids[source])),
                    "observed": count,
                    "threshold": selected.high_fanout_threshold,
                    "explanation": (
                        "One originator contacted many responders in this flow window; "
                        "validate expected discovery, orchestration, or scanning activity."
                    ),
                }
            )

    for source, flow_ids in reset_flow_ids.items():
        count = len(flow_ids)
        if count >= selected.reset_burst_threshold:
            findings.append(
                {
                    "signal": "reset_burst",
                    "severity": "medium",
                    "entity": source,
                    "flow_ids": sorted(set(flow_ids)),
                    "observed": count,
                    "threshold": selected.reset_burst_threshold,
                    "explanation": (
                        "One originator produced repeated reset-state flows; "
                        "validate service health, policy rejection, or authorized probing."
                    ),
                }
            )

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(
        findings,
        key=lambda item: (
            severity_rank.get(str(item["severity"]), 9),
            str(item["signal"]),
            str(item["entity"]),
        ),
    )
