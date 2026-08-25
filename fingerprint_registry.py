from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class FingerprintRule:
    name: str
    platform: str
    weight: int


DEFAULT_RULES: tuple[FingerprintRule, ...] = (
    FingerprintRule("android", "Android", 88),
    FingerprintRule("iphone", "iOS/iPadOS", 90),
    FingerprintRule("ipad", "iOS/iPadOS", 90),
    FingerprintRule("windows", "Windows", 82),
    FingerprintRule("ubuntu", "Linux", 84),
    FingerprintRule("debian", "Linux", 84),
    FingerprintRule("macbook", "macOS", 82),
    FingerprintRule("chromeos", "ChromeOS", 88),
    FingerprintRule("freebsd", "FreeBSD", 86),
)


def matching_rules(value: object, rules: tuple[FingerprintRule, ...] = DEFAULT_RULES) -> tuple[FingerprintRule, ...]:
    text = str(value or "").strip().lower()
    if not text:
        return ()
    return tuple(rule for rule in rules if rule.name in text)
