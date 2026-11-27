from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from typing import Any

MAX_AGENT_ROUNDS = 5
MAX_REGISTERED_TOOLS = 10
MAX_TOOL_CALLS_PER_ROUND = 10
MAX_AGENT_CONTEXT_BYTES = 64 * 1024
MAX_TOOL_SPEC_BYTES = 32 * 1024
MAX_TOOL_ARGUMENT_BYTES = 8 * 1024
MAX_TOOL_ARGUMENT_BYTES_PER_ROUND = 32 * 1024
MAX_TOOL_RESULT_BYTES = 16 * 1024
MAX_AGENT_TOOL_OUTPUT_BYTES = 64 * 1024


class ToolCallLimitExceeded(RuntimeError):
    pass


def encode_bounded_json(value: Any, *, max_bytes: int, label: str) -> tuple[str, int]:
    """Serialize strict compact JSON and enforce its UTF-8 byte budget."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        size = len(encoded.encode("utf-8"))
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise ToolCallLimitExceeded(f"{label} is not valid JSON") from exc
    if size > max_bytes:
        raise ToolCallLimitExceeded(f"{label} exceeds {max_bytes} bytes")
    return encoded, size


def validate_agent_context(
    context: Mapping[str, Any],
) -> tuple[dict[str, Any], str, int]:
    """Validate the initial evidence payload before any model call."""
    if not isinstance(context, Mapping):
        raise ToolCallLimitExceeded("agent context must be a mapping")
    normalized = dict(context)
    encoded, size = encode_bounded_json(
        normalized,
        max_bytes=MAX_AGENT_CONTEXT_BYTES,
        label="agent context",
    )
    return normalized, encoded, size


def validate_tool_specs(tool_specs: object) -> int:
    """Bound serialized provider tool definitions before a model request."""
    if not isinstance(tool_specs, list) or len(tool_specs) > MAX_REGISTERED_TOOLS:
        raise ToolCallLimitExceeded(
            f"agent supports at most {MAX_REGISTERED_TOOLS} registered tool definitions"
        )
    _, size = encode_bounded_json(
        tool_specs,
        max_bytes=MAX_TOOL_SPEC_BYTES,
        label="tool definitions",
    )
    return size


def parse_tool_arguments(value: object) -> tuple[dict[str, Any], int]:
    """Parse one bounded JSON argument object before invoking a registered tool."""
    if isinstance(value, str):
        try:
            raw_size = len(value.encode("utf-8"))
        except UnicodeError as exc:
            raise ToolCallLimitExceeded(
                "agent returned invalid tool arguments"
            ) from exc
        if raw_size > MAX_TOOL_ARGUMENT_BYTES:
            raise ToolCallLimitExceeded(
                f"tool arguments exceed {MAX_TOOL_ARGUMENT_BYTES} bytes"
            )
        try:
            parsed = json.loads(value)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ToolCallLimitExceeded(
                "agent returned invalid tool arguments"
            ) from exc
    elif isinstance(value, Mapping):
        parsed = dict(value)
    else:
        raise ToolCallLimitExceeded("agent returned invalid tool arguments")

    if not isinstance(parsed, Mapping):
        raise ToolCallLimitExceeded("agent returned invalid tool arguments")
    normalized = dict(parsed)
    _, size = encode_bounded_json(
        normalized,
        max_bytes=MAX_TOOL_ARGUMENT_BYTES,
        label="tool arguments",
    )
    return normalized, size


def serialize_tool_result(result: object) -> tuple[dict[str, Any], str, int]:
    """Require a JSON mapping and cap each registered tool's returned evidence."""
    if not isinstance(result, Mapping):
        raise ToolCallLimitExceeded("registered tool returned an invalid result")
    normalized = dict(result)
    encoded, size = encode_bounded_json(
        normalized,
        max_bytes=MAX_TOOL_RESULT_BYTES,
        label="tool result",
    )
    return normalized, encoded, size


def validate_max_rounds(max_rounds: int) -> int:
    """Reject caller-supplied budgets that could create unbounded provider spend."""
    if (
        isinstance(max_rounds, bool)
        or not isinstance(max_rounds, int)
        or not 1 <= max_rounds <= MAX_AGENT_ROUNDS
    ):
        raise ValueError(
            f"max_rounds must be an integer between 1 and {MAX_AGENT_ROUNDS}"
        )
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
    argument_bytes = 0
    for call in calls:
        if not isinstance(call, Mapping):
            raise ToolCallLimitExceeded("agent returned an invalid tool call")
        name = str(call.get("name", ""))
        if name not in tools:
            raise KeyError(f"AI requested unregistered tool: {name}")
        arguments = call.get("arguments", {})
        if arguments is None:
            arguments = {}
        normalized, size = parse_tool_arguments(arguments)
        argument_bytes += size
        if argument_bytes > MAX_TOOL_ARGUMENT_BYTES_PER_ROUND:
            raise ToolCallLimitExceeded(
                f"tool arguments exceed {MAX_TOOL_ARGUMENT_BYTES_PER_ROUND} bytes per round"
            )
        prepared.append((name, normalized))
    return prepared


def run_agent_loop(
    model_call: Callable[
        [list[dict[str, Any]], list[dict[str, Any]]], Mapping[str, Any]
    ],
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
    context_data, _, _ = validate_agent_context(context)
    if len(tools) > MAX_REGISTERED_TOOLS:
        raise ToolCallLimitExceeded(
            f"agent supports at most {MAX_REGISTERED_TOOLS} registered tools"
        )
    tool_specs = [{"name": name} for name in tools]
    validate_tool_specs(tool_specs)

    messages: list[dict[str, Any]] = [{"role": "user", "content": context_data}]
    total_tool_output_bytes = 0
    for round_index in range(max_rounds):
        response = dict(model_call(messages, tool_specs))
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
            normalized, _, result_bytes = serialize_tool_result(result)
            total_tool_output_bytes += result_bytes
            if total_tool_output_bytes > MAX_AGENT_TOOL_OUTPUT_BYTES:
                raise ToolCallLimitExceeded(
                    f"agent tool results exceed {MAX_AGENT_TOOL_OUTPUT_BYTES} bytes per invocation"
                )
            messages.append({"role": "tool", "name": name, "content": normalized})

    raise ToolCallLimitExceeded(f"agent exceeded {max_rounds} model rounds")
