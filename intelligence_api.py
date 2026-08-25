from __future__ import annotations

from collections.abc import Mapping
from typing import TypedDict

from behavior_report import BehaviorSummary, summarize_behavior
from os_fingerprint import OSFingerprintDict, fingerprint_os


class IntelligenceSnapshot(TypedDict):
    asset_id: object
    fingerprint: OSFingerprintDict
    behavior: BehaviorSummary


def asset_intelligence(
    *, asset: Mapping[str, object], findings: list[Mapping[str, object]] | None = None
) -> IntelligenceSnapshot:
    """Return a serializable intelligence snapshot for an inventory asset."""
    services = asset.get("services")
    service_map = services if isinstance(services, Mapping) else {}
    ttl = asset.get("ttl")
    ttl_value = ttl if isinstance(ttl, int) else None
    fingerprint = fingerprint_os(
        hostname=asset.get("hostname"),
        manufacturer=asset.get("manufacturer"),
        device_family=asset.get("device_family"),
        device_type=asset.get("device_type"),
        ttl=ttl_value,
        services=service_map,
    )
    behavior = summarize_behavior(findings or [])
    return {
        "asset_id": asset.get("id") or asset.get("ip") or asset.get("mac"),
        "fingerprint": fingerprint.as_dict(),
        "behavior": behavior,
    }
