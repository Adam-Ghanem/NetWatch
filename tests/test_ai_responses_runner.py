from types import SimpleNamespace

import pytest

from ai_agent_loop import (
    MAX_AGENT_ROUNDS,
    MAX_REGISTERED_TOOLS,
    MAX_TOOL_CALLS_PER_ROUND,
    ToolCallLimitExceeded,
)
from ai_responses_runner import run_responses_agent


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


def _run(client, *, tools=None, tool_specs=None, max_rounds=5):
    return run_responses_agent(
        client,
        model="test-model",
        context={},
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
        tools={"asset_snapshot": lambda args: {"id": args["id"], "services": []}},
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
    executed = []
    calls = [_function_call("read", call_id=f"c{index}") for index in range(MAX_TOOL_CALLS_PER_ROUND + 1)]
    client = FakeClient(calls)

    with pytest.raises(ToolCallLimitExceeded, match="tool calls"):
        _run(
            client,
            tool_specs=[{"type": "function", "name": "read"}],
            tools={"read": lambda _: executed.append(True) or {}},
        )
    assert executed == []


def test_runner_prevalidates_batch_before_executing_any_tool():
    executed = []
    client = FakeClient([_function_call("read"), _function_call("shell", call_id="c2")])

    with pytest.raises(KeyError, match="shell"):
        _run(
            client,
            tool_specs=[{"type": "function", "name": "read"}],
            tools={"read": lambda _: executed.append(True) or {}},
        )
    assert executed == []


def test_runner_does_not_execute_unconsumed_last_round_batch():
    executed = []
    client = FakeClient([_function_call("read")])

    with pytest.raises(ToolCallLimitExceeded, match="maximum model rounds"):
        _run(
            client,
            tool_specs=[{"type": "function", "name": "read"}],
            tools={"read": lambda _: executed.append(True) or {}},
            max_rounds=1,
        )
    assert executed == []


def test_runner_caps_tool_definitions_before_provider_call():
    client = FakeClient()
    specs = [{"type": "function", "name": f"tool-{index}"} for index in range(MAX_REGISTERED_TOOLS + 1)]
    tools = {f"tool-{index}": lambda _: {} for index in range(MAX_REGISTERED_TOOLS + 1)}

    with pytest.raises(ToolCallLimitExceeded, match="registered tools"):
        _run(client, tool_specs=specs, tools=tools)
    assert client.responses.round == 0
