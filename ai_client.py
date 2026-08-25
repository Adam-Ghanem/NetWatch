from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from typing import Any

try:
    from openai import OpenAI
except ImportError:  # optional dependency
    OpenAI = None  # type: ignore[assignment,misc]


class AIConfigurationError(RuntimeError):
    pass


def _client() -> Any:
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise AIConfigurationError("OPENAI_API_KEY is not configured")
    if OpenAI is None:
        raise AIConfigurationError("Install the optional OpenAI SDK to enable AI")
    return OpenAI(api_key=key)


def analyze_with_ai(
    *,
    asset: Mapping[str, object],
    findings: Sequence[Mapping[str, object]] = (),
    model: str | None = None,
) -> str:
    """Send bounded NetWatch evidence to an explicitly configured OpenAI model."""
    selected_model = model or os.getenv("NETWATCH_AI_MODEL", "gpt-5-mini")
    payload = {"asset": dict(asset), "findings": [dict(item) for item in findings]}
    response = _client().responses.create(
        model=selected_model,
        instructions=(
            "You are NetWatch's defensive security analysis assistant. "
            "Analyze only the supplied evidence. Do not invent facts, credentials, "
            "vulnerabilities, or observations. Return concise defensive guidance."
        ),
        input=json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
    )
    return response.output_text
