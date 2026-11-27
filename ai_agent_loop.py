from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

MAX_AGENT_ROUNDS = 5
MAX_REGISTERED_TOOLS = 10
MAX_TOOL_CALLS_PER_ROUND = 10


class ToolCallLimitExceeded(RuntimeError):
    pass


def validate_max_rounds(max_rounds: int) -> int:
    """Reject caller-supplied budgets that could create unbounded provider spend."""
    if (
        isinstance(max_rounds, bool)
        or not isinstance(max_rounds, int)
        or not 1 <= max_rounds <= MAX_AGENT_ROUNDS
    ):
        raise ValueError(f"max_rounds must be an integer between 1 and {MAX_AGENT_ROUNDS}")
    return max_rounds


def _prepare_tool_calls(
    calls: object,
    tools: Mapping[str, Callable[[dict[str, Any]], Mapping[str, Any]]],
) -> list[tuple[str, dict[str, Any]]]:
    """Validate a complete batch before executing any registered tool."""
    if not isinstance(calls, (list, tuple)):
        raise ToolCallLimitExceeded("agent returned an invalid tool-call batch")
    if len(calls) > MAX_TOOL_CALLS_PER_ROUND:
        raise ToolCallLimitExceeded(
            f"agent exceeded {MAX_TOOL_CALLS_PER_ROUND} tool calls in one round"
        )

    prepared: list[tuple[str, dict[str, Any]]] = []
    for call in calls:
        if not isinstance(call, Mapping):
            raise ToolCallLimitExceeded("agent returned an invalid tool call")
        name = str(call.get("name", ""))
        if name not in tools:
            raise KeyError(f"AI requested unregistered tool: {name}")
        arguments = call.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise ToolCallLimitExceeded("agent returned invalid tool arguments")
        prepared.append((name, dict(arguments)))
    return prepared


def run_agent_loop(
    model_call: Callable[[list[dict[str, Any]], list[dict[str, Any]]], Mapping[str, Any]],
    context: Mapping[str, Any],
    tools: Mapping[str, Callable[[dict[str, Any]], Mapping[str, Any]]],
    *,
    max_rounds: int = 5,
) -> Mapping[str, Any]:
    """Execute a bounded tool-calling loop over already-collected evidence.

    model_call is deliberately injected so the loop is provider-neutral and easy
    to test. Tools must be explicitly registered; no arbitrary function execution
    is exposed to the model. max_rounds counts model calls, not tool batches.
    """
    max_rounds = validate_max_rounds(max_rounds)
    if len(tools) > MAX_REGISTERED_TOOLS:
        raise ToolCallLimitExceeded(
            f"agent supports at most {MAX_REGISTERED_TOOLS} registered tools"
        )

    messages: list[dict[str, Any]] = [{"role": "user", "content": dict(context)}]
    for round_index in range(max_rounds):
        response = dict(model_call(messages, [{"name": name} for name in tools]))
        raw_calls = response.get("tool_calls") or []
        if not raw_calls:
            return response

        calls = _prepare_tool_calls(raw_calls, tools)
        if round_index == max_rounds - 1:
            raise ToolCallLimitExceeded(
                "agent reached the maximum model rounds before completing the tool batch"
            )

        for name, arguments in calls:
            result = tools[name](arguments)
            if not isinstance(result, Mapping):
                raise ToolCallLimitExceeded("registered tool returned an invalid result")
            messages.append({"role": "tool", "name": name, "content": dict(result)})

    raise ToolCallLimitExceeded(f"agent exceeded {max_rounds} model rounds")
