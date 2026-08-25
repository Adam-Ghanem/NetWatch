from __future__ import annotations

from collections.abc import Mapping, Protocol


class AIProvider(Protocol):
    def analyze(self, context: Mapping[str, object]) -> str: ...


class DisabledAIProvider:
    """Safe default: keeps NetWatch fully local until an explicit provider is configured."""

    def analyze(self, context: Mapping[str, object]) -> str:
        return "AI provider is disabled; use the deterministic analyst assessment."
