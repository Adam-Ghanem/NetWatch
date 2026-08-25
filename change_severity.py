from __future__ import annotations


def change_severity(kind: str, *, exposure_delta: int = 0) -> str:
    """Classify a change without making vulnerability claims."""
    name = kind.strip().lower()
    if name in {"identity_changed", "device_family_changed"}:
        return "high"
    if name in {"new_port", "new_service", "exposure_shift"} and exposure_delta > 0:
        return "high"
    if name in {"new_port", "new_service", "exposure_shift"}:
        return "medium"
    return "low"
