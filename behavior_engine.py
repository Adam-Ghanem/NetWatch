from __future__ import annotations

"""Deterministic, local-only behavioral baselines for NetWatch assets.

This module intentionally contains no network access, persistence, or ML runtime.
It converts bounded historical asset observations into a stable profile and
explainable anomaly candidates. Callers decide how/where observations are stored
and whether a finding should become an alert.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TypeVar

StableValue = TypeVar("StableValue", str, int)

DEFAULT_MIN_BASELINE_OBSERVATIONS = 3
DEFAULT_MAX_BASELINE_OBSERVATIONS = 30
DEFAULT_PORT_PERSISTENCE = 0.60
DEFAULT_CHANGE_THRESHOLD = 0.50


@dataclass(frozen=True)
class AssetObservation:
    """A normalized, payload-free observation of one authorized asset."""

    observed_at: str
    hostname: str = ""
    mac_address: str = ""
    manufacturer: str = ""
    device_family: str = ""
    open_ports: tuple[int, ...] = ()
    services: tuple[str, ...] = ()
    criticality: str = "Medium"
    exposure_score: int = 0

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "AssetObservation":
        def _as_int(raw: object, default: int = 0) -> int:
            if isinstance(raw, bool):
                return int(raw)
            if isinstance(raw, int):
                return raw
            if isinstance(raw, float):
                return int(raw)
            if isinstance(raw, str):
                try:
                    return int(raw.strip())
                except ValueError:
                    return default
            return default

        def _ports(raw: object) -> tuple[int, ...]:
            if not isinstance(raw, (list, tuple, set)):
                return ()
            ports = {_as_int(port, default=-1) for port in raw}
            return tuple(sorted(port for port in ports if 1 <= port <= 65535))

        def _strings(raw: object) -> tuple[str, ...]:
            if not isinstance(raw, (list, tuple, set)):
                return ()
            return tuple(sorted({str(item).strip() for item in raw if str(item).strip()}))

        return cls(
            observed_at=str(value.get("observed_at", "")),
            hostname=str(value.get("hostname", "")).strip(),
            mac_address=str(value.get("mac_address", "")).strip().lower(),
            manufacturer=str(value.get("manufacturer", "")).strip(),
            device_family=str(value.get("device_family", "")).strip(),
            open_ports=_ports(value.get("open_ports", ())),
            services=_strings(value.get("services", ())),
            criticality=str(value.get("criticality", "Medium")),
            exposure_score=max(0, min(100, _as_int(value.get("exposure_score", 0)))),
        )


@dataclass(frozen=True)
class BehaviorBaseline:
    observations: int
    hostnames: tuple[str, ...]
    mac_addresses: tuple[str, ...]
    manufacturers: tuple[str, ...]
    device_families: tuple[str, ...]
    stable_ports: tuple[int, ...]
    stable_services: tuple[str, ...]
    exposure_score_min: int
    exposure_score_max: int
    exposure_score_median: float


@dataclass(frozen=True)
class BehaviorFinding:
    kind: str
    severity: str
    confidence: str
    summary: str
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "evidence": list(self.evidence),
        }


def _clean(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted({v.strip() for v in values if v and v.strip()}))


def _median(values: Sequence[int]) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def build_baseline(
    observations: Iterable[AssetObservation],
    *,
    min_observations: int = DEFAULT_MIN_BASELINE_OBSERVATIONS,
    max_observations: int = DEFAULT_MAX_BASELINE_OBSERVATIONS,
    port_persistence: float = DEFAULT_PORT_PERSISTENCE,
) -> BehaviorBaseline | None:
    """Build a conservative baseline from the newest bounded observations.

    A baseline is deliberately unavailable until enough observations exist. This
    avoids turning first-seen assets and sparse data into noisy anomalies.
    """
    if min_observations < 1 or max_observations < min_observations:
        raise ValueError("invalid baseline observation bounds")
    if not 0.0 < port_persistence <= 1.0:
        raise ValueError("port_persistence must be in (0, 1]")

    items = list(observations)[-max_observations:]
    if len(items) < min_observations:
        return None

    def stable(values: Iterable[Iterable[StableValue]]) -> tuple[StableValue, ...]:
        buckets: dict[StableValue, int] = {}
        for row in values:
            for value in row:
                buckets[value] = buckets.get(value, 0) + 1
        threshold = len(items) * port_persistence
        return tuple(sorted(value for value, count in buckets.items() if count >= threshold))

    return BehaviorBaseline(
        observations=len(items),
        hostnames=_clean(item.hostname for item in items),
        mac_addresses=_clean(item.mac_address for item in items),
        manufacturers=_clean(item.manufacturer for item in items),
        device_families=_clean(item.device_family for item in items),
        stable_ports=stable(item.open_ports for item in items),
        stable_services=stable(item.services for item in items),
        exposure_score_min=min(item.exposure_score for item in items),
        exposure_score_max=max(item.exposure_score for item in items),
        exposure_score_median=_median([item.exposure_score for item in items]),
    )


def _severity(kind: str, observation: AssetObservation) -> str:
    if (
        kind in {"identity_changed", "new_service", "new_port"}
        and observation.criticality == "Critical"
    ):
        return "High"
    if kind in {"identity_changed", "new_service", "new_port", "exposure_shift"}:
        return "Medium"
    return "Low"


def detect_behavior_changes(
    baseline: BehaviorBaseline | None,
    observation: AssetObservation,
    *,
    change_threshold: float = DEFAULT_CHANGE_THRESHOLD,
) -> tuple[BehaviorFinding, ...]:
    """Compare one observation with a baseline and return explainable findings."""
    if baseline is None:
        return ()
    if not 0.0 < change_threshold <= 1.0:
        raise ValueError("change_threshold must be in (0, 1]")

    findings: list[BehaviorFinding] = []
    baseline_ports = set(baseline.stable_ports)
    current_ports = set(observation.open_ports)
    new_ports = sorted(current_ports - baseline_ports)
    if new_ports:
        findings.append(
            BehaviorFinding(
                kind="new_port",
                severity=_severity("new_port", observation),
                confidence="High" if baseline.observations >= 5 else "Medium",
                summary=f"{len(new_ports)} port(s) are new relative to the asset baseline.",
                evidence=(
                    f"new_ports={','.join(map(str, new_ports))}",
                    f"baseline_observations={baseline.observations}",
                ),
            )
        )

    baseline_services = set(baseline.stable_services)
    current_services = set(observation.services)
    new_services = sorted(current_services - baseline_services)
    if new_services:
        findings.append(
            BehaviorFinding(
                kind="new_service",
                severity=_severity("new_service", observation),
                confidence="High" if baseline.observations >= 5 else "Medium",
                summary=f"{len(new_services)} service(s) are new relative to the asset baseline.",
                evidence=(
                    f"new_services={','.join(new_services)}",
                    f"baseline_observations={baseline.observations}",
                ),
            )
        )

    known_identity = set(baseline.mac_addresses)
    if observation.mac_address and known_identity and observation.mac_address not in known_identity:
        findings.append(
            BehaviorFinding(
                kind="identity_changed",
                severity=_severity("identity_changed", observation),
                confidence="High" if baseline.observations >= 5 else "Medium",
                summary="The asset MAC identity differs from its established baseline.",
                evidence=(
                    f"current_mac={observation.mac_address}",
                    f"baseline_macs={','.join(sorted(known_identity))}",
                ),
            )
        )

    if (
        baseline.device_families
        and observation.device_family
        and observation.device_family not in baseline.device_families
    ):
        findings.append(
            BehaviorFinding(
                kind="device_family_changed",
                severity=_severity("identity_changed", observation),
                confidence="Medium",
                summary="The observed device family differs from the established baseline.",
                evidence=(
                    f"current_family={observation.device_family}",
                    f"baseline_families={','.join(baseline.device_families)}",
                ),
            )
        )

    score_delta = abs(observation.exposure_score - baseline.exposure_score_median)
    if score_delta >= max(10.0, baseline.exposure_score_median * change_threshold):
        findings.append(
            BehaviorFinding(
                kind="exposure_shift",
                severity=_severity("exposure_shift", observation),
                confidence="Medium",
                summary="The asset exposure score moved materially from its baseline.",
                evidence=(
                    f"current_score={observation.exposure_score}",
                    f"baseline_median={baseline.exposure_score_median:.1f}",
                    f"delta={score_delta:.1f}",
                ),
            )
        )

    return tuple(findings)


def evaluate_observations(
    observations: Iterable[AssetObservation],
    *,
    min_observations: int = DEFAULT_MIN_BASELINE_OBSERVATIONS,
) -> tuple[BehaviorBaseline | None, tuple[BehaviorFinding, ...]]:
    """Convenience API: baseline all but the newest observation, then evaluate it."""
    items = list(observations)
    if not items:
        return None, ()
    baseline = build_baseline(items[:-1], min_observations=min_observations)
    return baseline, detect_behavior_changes(baseline, items[-1])
