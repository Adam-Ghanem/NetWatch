from __future__ import annotations

from typing import Literal

CipherPosture = Literal["modern_aead", "legacy_unsafe", "unknown"]

# Deliberately narrow evidence sets. Unknown ciphers stay unknown instead of being
# graded from naming heuristics that could overstate risk.
_MODERN_AEAD_MARKERS = (
    "CHACHA20_POLY1305",
    "AES_128_GCM",
    "AES_256_GCM",
    "AES_128_CCM",
    "AES_256_CCM",
)
_LEGACY_UNSAFE_MARKERS = (
    "RC4",
    "3DES",
    "DES_CBC3",
    "DES_EDE3",
    "_NULL_",
    "WITH_NULL_",
    "EXPORT",
)


def tls_cipher_posture(cipher: object) -> CipherPosture:
    """Classify only cipher names with strong, name-local evidence.

    This is intentionally not a general TLS grading engine. CBC suites, custom
    provider names, and any unfamiliar value remain ``unknown`` so NetWatch does
    not infer weakness without enough evidence.
    """
    if not isinstance(cipher, str):
        return "unknown"
    normalized = cipher.strip().upper().replace("-", "_")
    if not normalized:
        return "unknown"
    if any(marker in normalized for marker in _LEGACY_UNSAFE_MARKERS):
        return "legacy_unsafe"
    if any(marker in normalized for marker in _MODERN_AEAD_MARKERS):
        return "modern_aead"
    return "unknown"


def is_confirmed_cipher_regression(previous: object, current: object) -> bool:
    """Return true only for a known-modern AEAD -> known-legacy transition."""
    return (
        tls_cipher_posture(previous) == "modern_aead"
        and tls_cipher_posture(current) == "legacy_unsafe"
    )
