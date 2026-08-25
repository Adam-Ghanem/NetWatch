from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any


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
    if max_rounds < 1:
        raise ValueError("max_rounds must be >= 1")

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

    for _ in range(max_rounds):
        calls = [item for item in getattr(response, "output", []) or [] if getattr(item, "type", None) == "function_call"]
        if not calls:
            return getattr(response, "output_text", "")

        outputs: list[dict[str, Any]] = []
        for call in calls:
            name = getattr(call, "name", "")
            if name not in tools:
                raise KeyError(f"AI requested unregistered tool: {name}")
            arguments = json.loads(getattr(call, "arguments", "{}"))
            result = tools[name](arguments)
            outputs.append({
                "type": "function_call_output",
                "call_id": getattr(call, "call_id", ""),
                "output": json.dumps(dict(result), ensure_ascii=False),
            })

        response = client.responses.create(
            model=model,
            instructions="Continue the defensive investigation using only the tool results provided.",
            previous_response_id=getattr(response, "id", None),
            input=outputs,
            tools=tool_specs,
        )

    raise RuntimeError(f"AI agent exceeded {max_rounds} rounds")
