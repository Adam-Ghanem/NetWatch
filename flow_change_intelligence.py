from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class FlowChangePolicy:
    """Bounds and thresholds for comparing metadata-only flow snapshots."""

    max_flows_per_snapshot: int = 1_000
    max_findings: int = 500
    min_volume_bytes: int = 4_096
    volume_ratio_threshold: float = 3.0

    def validate(self) -> None:
        if not 1 <= self.max_flows_per_snapshot <= 5_000:
            raise ValueError("Flow snapshot bound must be between 1 and 5000.")
        if not 1 <= self.max_findings <= 1_000:
            raise ValueError("Flow change finding limit must be between 1 and 1000.")
        if not 0 <= self.min_volume_bytes <= 1_000_000_000_000:
            raise ValueError("Minimum volume bytes must be between 0 and 1000000000000.")
        if not 1.1 <= self.volume_ratio_threshold <= 100.0:
            raise ValueError("Volume ratio threshold must be between 1.1 and 100.")


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


def _safe_nonnegative_int(value: object) -> int:
    try:
        parsed = int(str(value or 0))
    except (TypeError, ValueError):
        return 0
    return max(0, parsed)


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


def _service_volumes(
    flows: Iterable[dict[str, object]],
) -> dict[tuple[str, int, str, str], int]:
    values: dict[tuple[str, int, str, str], int] = {}
    for flow in flows:
        key = _service_key(flow)
        if key is None:
            continue
        values[key] = values.get(key, 0) + _safe_nonnegative_int(flow.get("bytes"))
    return values


def _service_entity(key: tuple[str, int, str, str]) -> str:
    ip_address, port, protocol, _ = key
    return f"{ip_address}:{port}/{protocol}"


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
    previous_services = _services(previous_flows)
    current_services = _services(current_flows)
    previous_service_keys = set(previous_services)
    current_service_keys = set(current_services)
    previous_volumes = _service_volumes(previous_flows)
    current_volumes = _service_volumes(current_flows)

    findings: list[dict[str, object]] = []
    for ip_address in sorted(current_ips - previous_ips):
        findings.append(
            {
                "change": "new_endpoint",
                "severity": "info",
                "entity": ip_address,
                "explanation": (
                    f"Endpoint {ip_address} appears in the current flow snapshot "
                    "but not the baseline."
                ),
            }
        )

    for ip_address in sorted(previous_ips - current_ips):
        findings.append(
            {
                "change": "missing_endpoint",
                "severity": "info",
                "entity": ip_address,
                "explanation": (
                    f"Endpoint {ip_address} was observed in the baseline but is absent "
                    "from the current flow snapshot."
                ),
            }
        )

    for key in sorted(current_service_keys - previous_service_keys):
        _, _, _, service = key
        findings.append(
            {
                "change": "new_service",
                "severity": "review",
                "entity": _service_entity(key),
                "service": service,
                "flow_ids": sorted(current_services[key]),
                "explanation": (
                    f"Service {service} is newly observed on {_service_entity(key)} "
                    "relative to the baseline snapshot."
                ),
            }
        )

    for key in sorted(previous_service_keys - current_service_keys):
        _, _, _, service = key
        findings.append(
            {
                "change": "missing_service",
                "severity": "info",
                "entity": _service_entity(key),
                "service": service,
                "flow_ids": sorted(previous_services[key]),
                "explanation": (
                    f"Service {service} was observed on {_service_entity(key)} in the baseline "
                    "but is absent from the current snapshot."
                ),
            }
        )

    for key in sorted(previous_service_keys & current_service_keys):
        baseline_bytes = previous_volumes.get(key, 0)
        current_bytes = current_volumes.get(key, 0)
        if max(baseline_bytes, current_bytes) < selected.min_volume_bytes:
            continue
        low = min(baseline_bytes, current_bytes)
        high = max(baseline_bytes, current_bytes)
        if low == 0:
            ratio = float("inf") if high > 0 else 1.0
        else:
            ratio = high / low
        if ratio < selected.volume_ratio_threshold:
            continue

        direction = "increase" if current_bytes > baseline_bytes else "decrease"
        findings.append(
            {
                "change": f"traffic_volume_{direction}",
                "severity": "review",
                "entity": _service_entity(key),
                "service": key[3],
                "baseline_bytes": baseline_bytes,
                "current_bytes": current_bytes,
                "ratio": round(ratio, 2) if ratio != float("inf") else "infinite",
                "flow_ids": sorted(current_services[key]),
                "explanation": (
                    f"Observed traffic volume for {key[3]} on {_service_entity(key)} changed "
                    f"from {baseline_bytes} to {current_bytes} bytes, exceeding the configured "
                    f"{selected.volume_ratio_threshold:g}x drift threshold."
                ),
            }
        )

    return findings[: selected.max_findings]
