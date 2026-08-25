from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class OSFingerprint:
    platform: str
    family: str
    confidence: str
    score: int
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "family": self.family,
            "confidence": self.confidence,
            "score": self.score,
            "evidence": list(self.evidence),
        }


def _norm(value: object) -> str:
    return " ".join(str(value or "").strip().lower().split())


def fingerprint_os(
    *,
    hostname: object = "",
    manufacturer: object = "",
    device_family: object = "",
    device_type: object = "",
    ttl: int | None = None,
    services: Mapping[object, object] | None = None,
) -> OSFingerprint:
    """Deterministic OS/platform classification from bounded local evidence."""
    text = " | ".join(
        _norm(value)
        for value in (hostname, manufacturer, device_family, device_type)
        if _norm(value)
    )
    service_text = " ".join(_norm(value) for value in (services or {}).values())
    scores: dict[str, int] = {}
    evidence: dict[str, list[str]] = {}

    def add(platform: str, points: int, reason: str) -> None:
        scores[platform] = scores.get(platform, 0) + points
        evidence.setdefault(platform, []).append(reason)

    if any(x in text for x in ("iphone", "ipad", "ios", "apple iphone", "apple ipad")):
        add("iOS/iPadOS", 90, "Apple mobile identity evidence")
    if any(x in text for x in ("android", "pixel", "galaxy", "redmi", "xiaomi", "oneplus", "oppo", "realme")):
        add("Android", 88, "Android/mobile identity evidence")
    if "mac" in text or "macbook" in text or "imac" in text:
        add("macOS", 82, "Apple computer identity evidence")
    if any(x in text for x in ("windows", "win32", "microsoft")):
        add("Windows", 82, "Windows identity evidence")
    if any(x in text for x in ("linux", "ubuntu", "debian", "fedora", "arch", "raspberry pi")):
        add("Linux", 84, "Linux identity evidence")
    if any(x in text for x in ("openwrt", "router", "gateway", "tp-link", "ubiquiti", "mikrotik", "zte")):
        add("Embedded Linux", 72, "network-device identity evidence")
    if any(x in text for x in ("freebsd", "free bsd")):
        add("FreeBSD", 86, "FreeBSD identity evidence")
    if "chromeos" in text or "chromebook" in text:
        add("ChromeOS", 88, "ChromeOS identity evidence")

    if "android" in service_text:
        add("Android", 30, "service metadata")
    if "microsoft" in service_text or "windows" in service_text:
        add("Windows", 25, "service metadata")
    if "openssh" in service_text or "linux" in service_text:
        add("Linux", 18, "service metadata")

    # TTL is only a weak signal; never let it override stronger identity evidence.
    if ttl is not None and 0 < int(ttl) <= 64:
        add("Unix-like", 8, "low-TTL network hint")
    elif ttl is not None and 64 < int(ttl) <= 128:
        add("Windows-like", 6, "TTL network hint")

    if not scores:
        return OSFingerprint("Unknown", "Unknown", "Low", 0, ("insufficient evidence",))

    ranked = sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    platform, score = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0
    if score >= 85 and score - second >= 20:
        confidence = "High"
    elif score >= 55 and score - second >= 10:
        confidence = "Medium"
    else:
        confidence = "Low"

    family = {
        "Android": "Mobile",
        "iOS/iPadOS": "Mobile",
        "macOS": "Desktop",
        "Windows": "Desktop",
        "Linux": "Desktop/Server",
        "Embedded Linux": "Embedded/Network",
        "FreeBSD": "Server/Network",
        "ChromeOS": "Desktop",
        "Unix-like": "Unix-like",
        "Windows-like": "Windows-like",
    }.get(platform, "Unknown")
    return OSFingerprint(platform, family, confidence, min(score, 100), tuple(evidence[platform]))
