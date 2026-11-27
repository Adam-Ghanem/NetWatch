from collections.abc import Callable, Mapping
from typing import Any

import pytest

from ai_agent_loop import (
    MAX_AGENT_ROUNDS,
    MAX_REGISTERED_TOOLS,
    MAX_TOOL_CALLS_PER_ROUND,
    ToolCallLimitExceeded,
    run_agent_loop,
)

Tool = Callable[[dict[str, Any]], Mapping[str, Any]]


def _record_execution(executed: list[bool], _args: dict[str, Any]) -> dict[str, Any]:
    executed.append(True)
    return {}


def test_agent_loop_executes_registered_tool_then_finishes():
    calls = []

    def model(messages, tools):
        calls.append((messages, tools))
        if len(calls) == 1:
            return {
                "tool_calls": [
                    {"name": "asset_history", "arguments": {"id": "a1"}}
                ]
            }
        return {"answer": "history reviewed"}

    result = run_agent_loop(
        model,
        {"asset": "a1"},
        {"asset_history": lambda args: {"id": args["id"], "events": []}},
    )
    assert result["answer"] == "history reviewed"
    assert len(calls) == 2


def test_agent_loop_rejects_unknown_tools():
    def model(messages, tools):
        return {"tool_calls": [{"name": "shell", "arguments": {}}]}

    with pytest.raises(KeyError):
        run_agent_loop(model, {}, {})


def test_agent_loop_is_bounded():
    def model(messages, tools):
        return {"tool_calls": [{"name": "ping", "arguments": {}}]}

    with pytest.raises(ToolCallLimitExceeded):
        run_agent_loop(model, {}, {"ping": lambda _: {}}, max_rounds=2)


@pytest.mark.parametrize("max_rounds", [0, MAX_AGENT_ROUNDS + 1, True, 1.5, "2"])
def test_agent_loop_rejects_invalid_round_budget_before_model_call(max_rounds):
    called = False

    def model(messages, tools):
        nonlocal called
        called = True
        return {}

    with pytest.raises(ValueError, match="max_rounds"):
        run_agent_loop(model, {}, {}, max_rounds=max_rounds)
    assert called is False


def test_agent_loop_rejects_oversized_tool_batch_before_execution():
    executed = []
    calls = [
        {"name": "read", "arguments": {}}
        for _ in range(MAX_TOOL_CALLS_PER_ROUND + 1)
    ]

    with pytest.raises(ToolCallLimitExceeded, match="tool calls"):
        run_agent_loop(
            lambda messages, tools: {"tool_calls": calls},
            {},
            {"read": lambda args: _record_execution(executed, args)},
        )

    assert executed == []


def test_agent_loop_prevalidates_batch_before_executing_any_tool():
    executed = []
    calls = [
        {"name": "read", "arguments": {}},
        {"name": "unregistered", "arguments": {}},
    ]

    with pytest.raises(KeyError, match="unregistered"):
        run_agent_loop(
            lambda messages, tools: {"tool_calls": calls},
            {},
            {"read": lambda args: _record_execution(executed, args)},
        )

    assert executed == []


@pytest.mark.parametrize("arguments", [[], "", False, 0])
def test_agent_loop_rejects_falsey_non_mapping_arguments_before_execution(arguments):
    executed = []

    with pytest.raises(ToolCallLimitExceeded, match="invalid tool arguments"):
        run_agent_loop(
            lambda messages, tools: {
                "tool_calls": [{"name": "read", "arguments": arguments}]
            },
            {},
            {"read": lambda args: _record_execution(executed, args)},
        )

    assert executed == []


def test_agent_loop_does_not_execute_unconsumed_last_round_batch():
    executed = []

    with pytest.raises(ToolCallLimitExceeded, match="maximum model rounds"):
        run_agent_loop(
            lambda messages, tools: {
                "tool_calls": [{"name": "read", "arguments": {}}]
            },
            {},
            {"read": lambda args: _record_execution(executed, args)},
            max_rounds=1,
        )

    assert executed == []


def test_agent_loop_caps_registered_tool_count_before_model_call():
    called = False
    tools: dict[str, Tool] = {
        f"tool-{index}": lambda _: {}
        for index in range(MAX_REGISTERED_TOOLS + 1)
    }

    def model(messages, registered):
        nonlocal called
        called = True
        return {}

    with pytest.raises(ToolCallLimitExceeded, match="registered tools"):
        run_agent_loop(model, {}, tools)
    assert called is False
