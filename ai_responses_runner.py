from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

from ai_agent_loop import (
    MAX_REGISTERED_TOOLS,
    MAX_TOOL_CALLS_PER_ROUND,
    ToolCallLimitExceeded,
    validate_max_rounds,
)


def run_responses_agent(
    client: Any,
    *,
    model: str,
    context: Mapping[str, Any],
    tool_specs: list[dict[str, Any]],
    tools: Mapping[str, Callable[[dict[str, Any]], Mapping[str, Any]]],
    max_rounds: int = 5,
) -> str:
    """Run a bounded OpenAI Responses tool-calling loop over NetWatch evidence."""
    max_rounds = validate_max_rounds(max_rounds)
    if len(tools) > MAX_REGISTERED_TOOLS or len(tool_specs) > MAX_REGISTERED_TOOLS:
        raise ToolCallLimitExceeded(
            f"agent supports at most {MAX_REGISTERED_TOOLS} registered tools"
        )

    response = client.responses.create(
        model=model,
        instructions=(
            "You are the NetWatch defensive security agent. Analyze only supplied evidence. "
            "Use registered tools only when additional collected evidence is needed. "
            "Never invent observations or credentials and never perform offensive actions."
        ),
        input=json.dumps(dict(context), ensure_ascii=False),
        tools=tool_specs,
    )

    for round_index in range(max_rounds):
        calls = [
            item
            for item in getattr(response, "output", []) or []
            if getattr(item, "type", None) == "function_call"
        ]
        if not calls:
            return getattr(response, "output_text", "")

        if len(calls) > MAX_TOOL_CALLS_PER_ROUND:
            raise ToolCallLimitExceeded(
                f"agent exceeded {MAX_TOOL_CALLS_PER_ROUND} tool calls in one round"
            )

        prepared: list[tuple[str, str, dict[str, Any]]] = []
        for call in calls:
            name = getattr(call, "name", "")
            if name not in tools:
                raise KeyError(f"AI requested unregistered tool: {name}")
            try:
                arguments = json.loads(getattr(call, "arguments", "{}"))
            except (TypeError, json.JSONDecodeError) as exc:
                raise ToolCallLimitExceeded("agent returned invalid tool arguments") from exc
            if not isinstance(arguments, dict):
                raise ToolCallLimitExceeded("agent returned invalid tool arguments")
            prepared.append((name, getattr(call, "call_id", ""), arguments))

        if round_index == max_rounds - 1:
            raise ToolCallLimitExceeded(
                "agent reached the maximum model rounds before completing the tool batch"
            )

        outputs: list[dict[str, Any]] = []
        for name, call_id, arguments in prepared:
            result = tools[name](arguments)
            if not isinstance(result, Mapping):
                raise ToolCallLimitExceeded("registered tool returned an invalid result")
            outputs.append(
                {
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": json.dumps(dict(result), ensure_ascii=False),
                }
            )

        response = client.responses.create(
            model=model,
            instructions=(
                "Continue the defensive investigation using only the tool results provided."
            ),
            previous_response_id=getattr(response, "id", None),
            input=outputs,
            tools=tool_specs,
        )

    raise ToolCallLimitExceeded(f"agent exceeded {max_rounds} model rounds")
