from __future__ import annotations


def asset_label(*, platform: str, device_category: str) -> str:
    """Produce a stable human-readable asset label."""
    platform = platform.strip() or "Unknown"
    category = device_category.strip() or "device"
    return f"{platform} {category}" if platform != "Unknown" else category.title()
