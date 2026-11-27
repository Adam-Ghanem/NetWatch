from types import SimpleNamespace

import pytest

from ai_agent_loop import (
    MAX_AGENT_ROUNDS,
    MAX_REGISTERED_TOOLS,
    MAX_TOOL_CALLS_PER_ROUND,
    ToolCallLimitExceeded,
)
from ai_responses_runner import run_responses_agent


class FakeResponses:
    def __init__(self):
        self.round = 0

    def create(self, **kwargs):
        self.round += 1
        if self.round == 1:
            return SimpleNamespace(
                id="r1",
                output=[
                    SimpleNamespace(
                        type="function_call",
                        name="asset_snapshot",
                        call_id="c1",
                        arguments='{"id":"a1"}',
                    )
                ],
            )
        return SimpleNamespace(id="r2", output=[], output_text="final investigation")


class FakeClient:
    def __init__(self):
        self.responses = FakeResponses()


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
    class BadResponses:
        def create(self, **kwargs):
            return SimpleNamespace(
                id="r1",
                output=[
                    SimpleNamespace(
                        type="function_call", name="shell", call_id="c1", arguments="{}"
                    )
                ],
            )

    client = SimpleNamespace(responses=BadResponses())
    with pytest.raises(KeyError):
        run_responses_agent(client, model="test-model", context={}, tool_specs=[], tools={})


def test_runner_rejects_round_budget_above_hard_limit_before_provider_call():
    client = FakeClient()
    with pytest.raises(ValueError, match="max_rounds"):
        run_responses_agent(
            client,
            model="test-model",
            context={},
            tool_specs=[],
            tools={},
            max_rounds=MAX_AGENT_ROUNDS + 1,
        )
    assert client.responses.round == 0


def test_runner_rejects_oversized_tool_batch_before_execution():
    executed = []
    calls = [
        SimpleNamespace(
            type="function_call",
            name="read",
            call_id=f"c{index}",
            arguments="{}",
        )
        for index in range(MAX_TOOL_CALLS_PER_ROUND + 1)
    ]

    class ManyCalls:
        def create(self, **kwargs):
            return SimpleNamespace(id="r1", output=calls)

    client = SimpleNamespace(responses=ManyCalls())
    with pytest.raises(ToolCallLimitExceeded, match="tool calls"):
        run_responses_agent(
            client,
            model="test-model",
            context={},
            tool_specs=[{"type": "function", "name": "read"}],
            tools={"read": lambda _: executed.append(True) or {}},
        )
    assert executed == []


def test_runner_prevalidates_batch_before_executing_any_tool():
    executed = []
    calls = [
        SimpleNamespace(
            type="function_call", name="read", call_id="c1", arguments="{}"
        ),
        SimpleNamespace(
            type="function_call", name="shell", call_id="c2", arguments="{}"
        ),
    ]

    class MixedCalls:
        def create(self, **kwargs):
            return SimpleNamespace(id="r1", output=calls)

    client = SimpleNamespace(responses=MixedCalls())
    with pytest.raises(KeyError, match="shell"):
        run_responses_agent(
            client,
            model="test-model",
            context={},
            tool_specs=[{"type": "function", "name": "read"}],
            tools={"read": lambda _: executed.append(True) or {}},
        )
    assert executed == []


def test_runner_does_not_execute_unconsumed_last_round_batch():
    executed = []

    class OneCall:
        def create(self, **kwargs):
            return SimpleNamespace(
                id="r1",
                output=[
                    SimpleNamespace(
                        type="function_call",
                        name="read",
                        call_id="c1",
                        arguments="{}",
                    )
                ],
            )

    client = SimpleNamespace(responses=OneCall())
    with pytest.raises(ToolCallLimitExceeded, match="maximum model rounds"):
        run_responses_agent(
            client,
            model="test-model",
            context={},
            tool_specs=[{"type": "function", "name": "read"}],
            tools={"read": lambda _: executed.append(True) or {}},
            max_rounds=1,
        )
    assert executed == []


def test_runner_caps_tool_definitions_before_provider_call():
    client = FakeClient()
    specs = [
        {"type": "function", "name": f"tool-{index}"}
        for index in range(MAX_REGISTERED_TOOLS + 1)
    ]
    tools = {f"tool-{index}": lambda _: {} for index in range(MAX_REGISTERED_TOOLS + 1)}

    with pytest.raises(ToolCallLimitExceeded, match="registered tools"):
        run_responses_agent(
            client,
            model="test-model",
            context={},
            tool_specs=specs,
            tools=tools,
        )
    assert client.responses.round == 0
