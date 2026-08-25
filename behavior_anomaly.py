from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class BehaviorObservation:
    """A normalized observation used by the deterministic baseline engine."""

    asset: str
    open_ports: frozenset[int] = frozenset()
    services: frozenset[str] = frozenset()
    device_family: str = "Unknown"
    exposure_score: int = 0


@dataclass(frozen=True)
class BehaviorAnomaly:
    asset: str
    kind: str
    severity: str
    confidence: float
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "asset": self.asset,
            "kind": self.kind,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


def _as_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def _clean_ports(values: Iterable[object]) -> frozenset[int]:
    result: set[int] = set()
    for value in values:
        port = _as_int(value, default=-1)
        if 1 <= port <= 65535:
            result.add(port)
    return frozenset(result)


def normalize_observation(value: Mapping[str, object]) -> BehaviorObservation:
    ports = value.get("open_ports", value.get("ports", ()))
    services = value.get("services", ())
    if isinstance(ports, str):
        ports = [part.strip() for part in ports.split(",") if part.strip()]
    if isinstance(services, str):
        services = [part.strip().lower() for part in services.split(",") if part.strip()]
    return BehaviorObservation(
        asset=str(value.get("asset", value.get("ip_address", ""))).strip(),
        open_ports=_clean_ports(ports if isinstance(ports, Iterable) else ()),
        services=(
            frozenset(str(item).strip().lower() for item in services if str(item).strip())
            if isinstance(services, Iterable)
            else frozenset()
        ),
        device_family=str(value.get("device_family", "Unknown")).strip() or "Unknown",
        exposure_score=max(0, min(100, _as_int(value.get("exposure_score", 0)))),
    )


def detect_behavior_anomalies(
    baseline: BehaviorObservation,
    current: BehaviorObservation,
) -> tuple[BehaviorAnomaly, ...]:
    """Compare two trusted observations; no network access or speculative inference."""
    if baseline.asset != current.asset:
        raise ValueError("baseline and current observations must refer to the same asset")

    findings: list[BehaviorAnomaly] = []
    added_ports = sorted(current.open_ports - baseline.open_ports)
    removed_ports = sorted(baseline.open_ports - current.open_ports)
    if added_ports:
        severity = (
            "high" if any(port in {22, 23, 3389, 445, 5900} for port in added_ports) else "medium"
        )
        findings.append(
            BehaviorAnomaly(
                current.asset,
                "new_ports",
                severity,
                0.95,
                (f"new open ports: {', '.join(map(str, added_ports))}",),
            )
        )
    if removed_ports:
        findings.append(
            BehaviorAnomaly(
                current.asset,
                "ports_closed",
                "low",
                0.95,
                (f"ports no longer observed: {', '.join(map(str, removed_ports))}",),
            )
        )

    added_services = sorted(current.services - baseline.services)
    removed_services = sorted(baseline.services - current.services)
    if added_services:
        findings.append(
            BehaviorAnomaly(
                current.asset,
                "new_services",
                "medium",
                0.9,
                (f"new services: {', '.join(added_services)}",),
            )
        )
    if removed_services:
        findings.append(
            BehaviorAnomaly(
                current.asset,
                "services_removed",
                "low",
                0.9,
                (f"services no longer observed: {', '.join(removed_services)}",),
            )
        )

    if baseline.device_family != current.device_family and current.device_family != "Unknown":
        findings.append(
            BehaviorAnomaly(
                current.asset,
                "identity_shift",
                "high",
                0.9,
                (
                    f"device family changed from '{baseline.device_family}' "
                    f"to '{current.device_family}'",
                ),
            )
        )

    exposure_delta = current.exposure_score - baseline.exposure_score
    if exposure_delta >= 20:
        findings.append(
            BehaviorAnomaly(
                current.asset,
                "exposure_increase",
                "high",
                0.9,
                (f"exposure score increased by {exposure_delta} points",),
            )
        )
    elif exposure_delta <= -20:
        findings.append(
            BehaviorAnomaly(
                current.asset,
                "exposure_decrease",
                "info",
                0.85,
                (f"exposure score decreased by {abs(exposure_delta)} points",),
            )
        )

    return tuple(findings)
