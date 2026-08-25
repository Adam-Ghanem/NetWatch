from __future__ import annotations

from collections.abc import Mapping

from behavior_report import summarize_behavior
from os_fingerprint import fingerprint_os


def asset_intelligence(*, asset: Mapping[str, object], findings: list[Mapping[str, object]] | None = None) -> dict[str, object]:
    """Return a serializable intelligence snapshot for an inventory asset."""
    services = asset.get("services")
    service_map = services if isinstance(services, Mapping) else {}
    fingerprint = fingerprint_os(
        hostname=asset.get("hostname"),
        manufacturer=asset.get("manufacturer"),
        device_family=asset.get("device_family"),
        device_type=asset.get("device_type"),
        ttl=asset.get("ttl") if isinstance(asset.get("ttl"), int) else None,
        services=service_map,
    )
    behavior = summarize_behavior(findings or [])
    return {
        "asset_id": asset.get("id") or asset.get("ip") or asset.get("mac"),
        "fingerprint": fingerprint.as_dict(),
        "behavior": behavior,
    }
