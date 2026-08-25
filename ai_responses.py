from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def response_tool_specs(tools: Mapping[str, str]) -> list[dict[str, Any]]:
    """Build strict Responses API function definitions for registered evidence tools."""
    return [
        {
            "type": "function",
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {"id": {"type": "string"}},
                "additionalProperties": False,
            },
            "strict": True,
        }
        for name, description in tools.items()
    ]


def extract_function_calls(response: Any) -> list[dict[str, Any]]:
    """Normalize function calls from an SDK response into a small internal shape."""
    calls: list[dict[str, Any]] = []
    for item in getattr(response, "output", []) or []:
        if getattr(item, "type", None) == "function_call":
            calls.append({
                "name": getattr(item, "name", ""),
                "call_id": getattr(item, "call_id", ""),
                "arguments": getattr(item, "arguments", "{}"),
            })
    return calls
