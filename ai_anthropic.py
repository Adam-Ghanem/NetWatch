"""Anthropic Claude adapter for bounded, de-identified NetWatch Intelligence.

The provider never receives raw asset records or arbitrary tools. No redirects are
followed, and only schema-validated advisory output is accepted.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any, Callable

from pydantic import ValidationError

from ai_advisor import (
    AIProviderError,
    AIProviderResult,
    IntelligenceBrief,
    _bounded_int,
    _http_error,
    _open_without_redirects,
    api_key_is_usable,
    build_openai_request_payload,
)
from config import AI_MAX_OUTPUT_TOKENS, AI_TIMEOUT_SECONDS

ANTHROPIC_MESSAGES_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_VERSION = "2023-06-01"
_UNSUPPORTED_SCHEMA_KEYS = frozenset(
    {"minimum", "maximum", "multipleOf", "minLength", "maxLength", "maxItems"}
)


def _claude_schema(value: Any) -> Any:
    """Remove unsupported JSON Schema constraints; Pydantic checks them after output."""
    if isinstance(value, list):
        return [_claude_schema(item) for item in value]
    if not isinstance(value, dict):
        return value
    cleaned: dict[str, Any] = {}
    for key, item in value.items():
        if key in _UNSUPPORTED_SCHEMA_KEYS:
            continue
        if key == "minItems" and item not in (0, 1):
            continue
        cleaned[key] = _claude_schema(item)
    if cleaned.get("type") == "object":
        cleaned["additionalProperties"] = False
    return cleaned


def build_anthropic_request_payload(
    snapshot: dict[str, Any],
    *,
    model: str,
    safety_id: str,
    max_output_tokens: int = AI_MAX_OUTPUT_TOKENS,
) -> dict[str, Any]:
    """Reuse the exact safety instructions and de-identified context of OpenAI."""
    base = build_openai_request_payload(
        snapshot, model=model, safety_id=safety_id, max_output_tokens=max_output_tokens
    )
    return {
        "model": str(model)[:120],
        "max_tokens": base["max_output_tokens"],
        "system": base["input"][0]["content"],
        "messages": [{"role": "user", "content": base["input"][1]["content"]}],
        "output_config": {
            "format": {
                "type": "json_schema",
                "schema": _claude_schema(IntelligenceBrief.model_json_schema()),
            }
        },
    }


def parse_anthropic_response(payload: dict[str, Any]) -> AIProviderResult:
    stop_reason = payload.get("stop_reason")
    if stop_reason == "refusal":
        raise AIProviderError(
            "provider_refusal",
            "The intelligence provider declined this analysis.",
            http_status=422,
        )
    if stop_reason != "end_turn":
        raise AIProviderError(
            "invalid_provider_response",
            "The intelligence provider returned an incomplete analysis.",
            http_status=502,
        )
    content = payload.get("content")
    if not isinstance(content, list):
        content = []
    blocks = [
        block.get("text")
        for block in content
        if isinstance(block, dict)
        and block.get("type") == "text"
        and isinstance(block.get("text"), str)
    ]
    if not blocks:
        raise AIProviderError(
            "invalid_provider_response",
            "The intelligence provider returned no usable structured output.",
            http_status=502,
        )
    try:
        brief = IntelligenceBrief.model_validate_json("".join(blocks))
    except ValidationError as exc:
        raise AIProviderError(
            "invalid_provider_response",
            "The intelligence provider returned an invalid structured brief.",
            http_status=502,
        ) from exc
    usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
    request_id = str(payload.get("id", ""))
    return AIProviderResult(
        brief=brief,
        provider_request_id="".join(char for char in request_id if char.isalnum() or char in "_-")[
            :160
        ],
        input_tokens=_bounded_int(usage.get("input_tokens")),
        output_tokens=_bounded_int(usage.get("output_tokens")),
    )


def request_anthropic_intelligence_brief(
    snapshot: dict[str, Any],
    *,
    api_key: str,
    safety_id: str,
    model: str,
    timeout_seconds: int = AI_TIMEOUT_SECONDS,
    opener: Callable[..., Any] | None = None,
) -> AIProviderResult:
    if not api_key_is_usable(api_key):
        raise AIProviderError(
            "provider_not_configured", "The intelligence provider is not configured."
        )
    body = json.dumps(
        build_anthropic_request_payload(snapshot, model=model, safety_id=safety_id),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        ANTHROPIC_MESSAGES_URL,
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_API_VERSION,
            "Content-Type": "application/json",
            "User-Agent": "NetWatch/1.7",
        },
        method="POST",
    )
    transport = opener or _open_without_redirects
    try:
        with transport(
            request, timeout=max(5, min(int(timeout_seconds), 60))
        ) as response:  # nosec B310
            raw = response.read(1_000_001)
    except urllib.error.HTTPError as exc:
        raise _http_error(exc) from exc
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        raise AIProviderError(
            "provider_unavailable", "The intelligence provider is temporarily unavailable."
        ) from exc
    if len(raw) > 1_000_000:
        raise AIProviderError(
            "provider_response_too_large",
            "The intelligence provider returned an oversized response.",
            http_status=502,
        )
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AIProviderError(
            "invalid_provider_response",
            "The intelligence provider returned an invalid response.",
            http_status=502,
        ) from exc
    if not isinstance(payload, dict):
        raise AIProviderError(
            "invalid_provider_response",
            "The intelligence provider returned an invalid response.",
            http_status=502,
        )
    return parse_anthropic_response(payload)
