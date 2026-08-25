from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


class ToolCallLimitExceeded(RuntimeError):
    pass


def run_agent_loop(
    model_call: Callable[[list[dict[str, Any]], list[dict[str, Any]]], Mapping[str, Any]],
    context: Mapping[str, Any],
    tools: Mapping[str, Callable[[dict[str, Any]], Mapping[str, Any]]],
    *,
    max_rounds: int = 5,
) -> Mapping[str, Any]:
    """Execute a bounded tool-calling loop over already-collected evidence.

    `model_call` is deliberately injected so the loop is provider-neutral and easy
    to test. Tools must be explicitly registered; no arbitrary function execution
    is exposed to the model.
    """
    if max_rounds < 1:
        raise ValueError("max_rounds must be >= 1")

    messages: list[dict[str, Any]] = [{"role": "user", "content": dict(context)}]
    for _ in range(max_rounds):
        response = dict(model_call(messages, [{"name": name} for name in tools]))
        calls = response.get("tool_calls") or []
        if not calls:
            return response
        for call in calls:
            name = str(call.get("name", ""))
            if name not in tools:
                raise KeyError(f"AI requested unregistered tool: {name}")
            arguments = call.get("arguments") or {}
            result = dict(tools[name](dict(arguments)))
            messages.append({"role": "tool", "name": name, "content": result})

    raise ToolCallLimitExceeded(f"agent exceeded {max_rounds} rounds")
