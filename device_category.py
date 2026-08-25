from __future__ import annotations

from collections.abc import Mapping


def classify_device(*, hostname: object = "", manufacturer: object = "", device_type: object = "", platform: object = "") -> str:
    """Classify a device into a coarse operational category using explicit evidence."""
    text = " ".join(str(v or "").strip().lower() for v in (hostname, manufacturer, device_type, platform))
    if any(x in text for x in ("router", "gateway", "switch", "access point", "mikrotik", "ubiquiti", "zte")):
        return "network"
    if any(x in text for x in ("iphone", "ipad", "android", "pixel", "galaxy")):
        return "mobile"
    if any(x in text for x in ("printer", "canon", "epson", "brother", "hp printer")):
        return "printer"
    if any(x in text for x in ("camera", "cctv", "hikvision", "dahua")):
        return "camera"
    if any(x in text for x in ("tv", "smart-tv", "roku", "chromecast", "fire tv")):
        return "smart-tv"
    if any(x in text for x in ("server", "ubuntu", "debian", "linux", "windows server")):
        return "server"
    if any(x in text for x in ("windows", "macos", "macbook", "desktop", "laptop")):
        return "workstation"
    return "unknown"
