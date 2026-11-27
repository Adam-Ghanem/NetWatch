from collections.abc import Callable, Mapping
from types import SimpleNamespace
from typing import Any

import pytest

from ai_agent_loop import (
    MAX_AGENT_CONTEXT_BYTES,
    MAX_AGENT_ROUNDS,
    MAX_AGENT_TOOL_OUTPUT_BYTES,
    MAX_REGISTERED_TOOLS,
    MAX_TOOL_ARGUMENT_BYTES,
    MAX_TOOL_CALLS_PER_ROUND,
    MAX_TOOL_RESULT_BYTES,
    MAX_TOOL_SPEC_BYTES,
    ToolCallLimitExceeded,
)
from ai_responses_runner import run_responses_agent

Tool = Callable[[dict[str, Any]], Mapping[str, Any]]


def _record_execution(executed: list[bool], _args: dict[str, Any]) -> dict[str, Any]:
    executed.append(True)
    return {}


def _function_call(name, *, call_id="c1", arguments="{}"):
    return SimpleNamespace(
        type="function_call",
        name=name,
        call_id=call_id,
        arguments=arguments,
    )


class FakeResponses:
    def __init__(self, first_output=None):
        self.round = 0
        self.first_output = first_output or [
            _function_call("asset_snapshot", arguments='{"id":"a1"}')
        ]

    def create(self, **kwargs):
        self.round += 1
        if self.round == 1:
            return SimpleNamespace(id="r1", output=self.first_output)
        return SimpleNamespace(id="r2", output=[], output_text="final investigation")


class FakeClient:
    def __init__(self, first_output=None):
        self.responses = FakeResponses(first_output)


def _run(client, *, context=None, tools=None, tool_specs=None, max_rounds=5):
    return run_responses_agent(
        client,
        model="test-model",
        context=context or {},
        tool_specs=tool_specs or [],
        tools=tools or {},
        max_rounds=max_rounds,
    )


def test_runner_executes_tool_and_returns_final_text():
    client = FakeClient()
    result = run_responses_agent(
        client,
        model="test-model",
        context={"asset": "a1"},
        tool_specs=[{"type": "function", "name": "asset_snapshot"}],
        tools={
            "asset_snapshot": lambda args: {
                "id": args["id"],
                "services": [],
            },
        },
    )
    assert result == "final investigation"
    assert client.responses.round == 2


def test_runner_rejects_unregistered_tool():
    client = FakeClient([_function_call("shell")])
    with pytest.raises(KeyError):
        _run(client)


def test_runner_rejects_round_budget_above_hard_limit_before_provider_call():
    client = FakeClient()
    with pytest.raises(ValueError, match="max_rounds"):
        _run(client, max_rounds=MAX_AGENT_ROUNDS + 1)
    assert client.responses.round == 0


def test_runner_rejects_oversized_tool_batch_before_execution():
    executed: list[bool] = []
    calls = [
        _function_call("read", call_id=f"c{index}") for index in range(MAX_TOOL_CALLS_PER_ROUND + 1)
    ]
    client = FakeClient(calls)

    with pytest.raises(ToolCallLimitExceeded, match="tool calls"):
        _run(
            client,
            tool_specs=[{"type": "function", "name": "read"}],
            tools={"read": lambda args: _record_execution(executed, args)},
        )
    assert executed == []


def test_runner_prevalidates_batch_before_executing_any_tool():
    executed: list[bool] = []
    client = FakeClient(
        [
            _function_call("read"),
            _function_call("shell", call_id="c2"),
        ]
    )

    with pytest.raises(KeyError, match="shell"):
        _run(
            client,
            tool_specs=[{"type": "function", "name": "read"}],
            tools={"read": lambda args: _record_execution(executed, args)},
        )
    assert executed == []


def test_runner_does_not_execute_unconsumed_last_round_batch():
    executed: list[bool] = []
    client = FakeClient([_function_call("read")])

    with pytest.raises(ToolCallLimitExceeded, match="maximum model rounds"):
        _run(
            client,
            tool_specs=[{"type": "function", "name": "read"}],
            tools={"read": lambda args: _record_execution(executed, args)},
            max_rounds=1,
        )
    assert executed == []


def test_runner_caps_tool_definitions_before_provider_call():
    client = FakeClient()
    specs = [
        {"type": "function", "name": f"tool-{index}"} for index in range(MAX_REGISTERED_TOOLS + 1)
    ]
    tools: dict[str, Tool] = {
        f"tool-{index}": lambda _: {}
        for index in range(MAX_REGISTERED_TOOLS + 1)
    }

    with pytest.raises(ToolCallLimitExceeded, match="registered tools"):
        _run(client, tool_specs=specs, tools=tools)
    assert client.responses.round == 0


def test_runner_rejects_oversized_context_before_provider_call():
    client = FakeClient()

    with pytest.raises(ToolCallLimitExceeded, match="agent context"):
        _run(client, context={"evidence": "x" * MAX_AGENT_CONTEXT_BYTES})

    assert client.responses.round == 0


def test_runner_rejects_oversized_tool_definitions_before_provider_call():
    client = FakeClient()
    specs = [
        {
            "type": "function",
            "name": "read",
            "description": "x" * MAX_TOOL_SPEC_BYTES,
        }
    ]

    with pytest.raises(ToolCallLimitExceeded, match="tool definitions"):
        _run(client, tools={"read": lambda _: {}}, tool_specs=specs)

    assert client.responses.round == 0


def test_runner_rejects_oversized_tool_arguments_before_execution():
    executed: list[bool] = []
    arguments = '{"query":"' + ("x" * MAX_TOOL_ARGUMENT_BYTES) + '"}'
    client = FakeClient([_function_call("read", arguments=arguments)])

    with pytest.raises(ToolCallLimitExceeded, match="tool arguments"):
        _run(
            client,
            tools={"read": lambda args: _record_execution(executed, args)},
            tool_specs=[{"type": "function", "name": "read"}],
        )

    assert executed == []
    assert client.responses.round == 1


def test_runner_rejects_aggregate_tool_arguments_before_execution():
    executed: list[bool] = []
    calls = [
        _function_call(
            "read",
            call_id=f"c{index}",
            arguments='{"query":"' + ("x" * (MAX_TOOL_ARGUMENT_BYTES // 2)) + '"}',
        )
        for index in range(9)
    ]
    client = FakeClient(calls)

    with pytest.raises(ToolCallLimitExceeded, match="per round"):
        _run(
            client,
            tools={"read": lambda args: _record_execution(executed, args)},
            tool_specs=[{"type": "function", "name": "read"}],
        )

    assert executed == []
    assert client.responses.round == 1


def test_runner_rejects_oversized_tool_result_before_next_provider_call():
    client = FakeClient([_function_call("read")])

    with pytest.raises(ToolCallLimitExceeded, match="tool result"):
        _run(
            client,
            tools={"read": lambda _: {"evidence": "x" * MAX_TOOL_RESULT_BYTES}},
            tool_specs=[{"type": "function", "name": "read"}],
        )

    assert client.responses.round == 1


def test_runner_caps_cumulative_tool_results_before_next_provider_call():
    executed: list[bool] = []
    calls = [_function_call("read", call_id=f"c{index}") for index in range(5)]
    client = FakeClient(calls)

    def read(_args):
        executed.append(True)
        return {"evidence": "x" * 15000}

    with pytest.raises(ToolCallLimitExceeded, match=str(MAX_AGENT_TOOL_OUTPUT_BYTES)):
        _run(
            client,
            tools={"read": read},
            tool_specs=[{"type": "function", "name": "read"}],
        )

    assert len(executed) == 5
    assert client.responses.round == 1
