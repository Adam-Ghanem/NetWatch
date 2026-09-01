from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class FlowChangePolicy:
    """Bounds for comparing metadata-only flow snapshots."""

    max_flows_per_snapshot: int = 1_000
    max_findings: int = 500

    def validate(self) -> None:
        if not 1 <= self.max_flows_per_snapshot <= 5_000:
            raise ValueError("Flow snapshot bound must be between 1 and 5000.")
        if not 1 <= self.max_findings <= 1_000:
            raise ValueError("Flow change finding limit must be between 1 and 1000.")


def _bounded_flows(
    flows: Iterable[dict[str, object]],
    *,
    maximum: int,
) -> list[dict[str, object]]:
    items = list(flows)
    if len(items) > maximum:
        raise ValueError(f"Flow snapshot may contain at most {maximum} flows.")
    return items


def _text(value: object) -> str:
    return str(value or "").strip()


def _endpoint(flow: dict[str, object], key: str) -> dict[str, object]:
    value = flow.get(key)
    return value if isinstance(value, dict) else {}


def _endpoint_ips(flows: Iterable[dict[str, object]]) -> set[str]:
    values: set[str] = set()
    for flow in flows:
        for key in ("originator", "responder"):
            ip_address = _text(_endpoint(flow, key).get("ip"))
            if ip_address:
                values.add(ip_address)
    return values


def _service_key(flow: dict[str, object]) -> tuple[str, int, str, str] | None:
    responder = _endpoint(flow, "responder")
    ip_address = _text(responder.get("ip"))
    service = _text(flow.get("service")).lower()
    protocol = _text(flow.get("protocol")).lower()
    try:
        port = int(str(responder.get("port") or 0))
    except (TypeError, ValueError):
        port = 0
    if not ip_address or not service or not protocol or port < 1 or port > 65_535:
        return None
    return (ip_address, port, protocol, service)


def _services(
    flows: Iterable[dict[str, object]],
) -> dict[tuple[str, int, str, str], list[str]]:
    values: dict[tuple[str, int, str, str], list[str]] = {}
    for flow in flows:
        key = _service_key(flow)
        if key is None:
            continue
        flow_id = _text(flow.get("flow_id"))
        flow_ids = values.setdefault(key, [])
        if flow_id and flow_id not in flow_ids:
            flow_ids.append(flow_id)
    return values


def compare_flow_snapshots(
    previous: Iterable[dict[str, object]],
    current: Iterable[dict[str, object]],
    *,
    policy: FlowChangePolicy | None = None,
) -> list[dict[str, object]]:
    """Report deterministic baseline deltas without inspecting packet payloads."""
    selected = policy or FlowChangePolicy()
    selected.validate()
    previous_flows = _bounded_flows(
        previous,
        maximum=selected.max_flows_per_snapshot,
    )
    current_flows = _bounded_flows(
        current,
        maximum=selected.max_flows_per_snapshot,
    )

    previous_ips = _endpoint_ips(previous_flows)
    current_ips = _endpoint_ips(current_flows)
    current_services = _services(current_flows)
    previous_services = set(_services(previous_flows))

    findings: list[dict[str, object]] = []
    for ip_address in sorted(current_ips - previous_ips):
        findings.append(
            {
                "change": "new_endpoint",
                "severity": "info",
                "entity": ip_address,
                "explanation": (
                    f"Endpoint {ip_address} appears in the current flow snapshot but not the baseline."
                ),
            }
        )

    for key in sorted(set(current_services) - previous_services):
        ip_address, port, protocol, service = key
        findings.append(
            {
                "change": "new_service",
                "severity": "review",
                "entity": f"{ip_address}:{port}/{protocol}",
                "service": service,
                "flow_ids": sorted(current_services[key]),
                "explanation": (
                    f"Service {service} is newly observed on {ip_address}:{port}/{protocol} "
                    "relative to the baseline snapshot."
                ),
            }
        )

    return findings[: selected.max_findings]
