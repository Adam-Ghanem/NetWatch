from types import SimpleNamespace

import pytest

from ai_responses_runner import run_responses_agent


class FakeResponses:
    def __init__(self):
        self.round = 0

    def create(self, **kwargs):
        self.round += 1
        if self.round == 1:
            return SimpleNamespace(id="r1", output=[SimpleNamespace(type="function_call", name="asset_snapshot", call_id="c1", arguments='{"id":"a1"}')])
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
            return SimpleNamespace(id="r1", output=[SimpleNamespace(type="function_call", name="shell", call_id="c1", arguments="{}")])

    client = SimpleNamespace(responses=BadResponses())
    with pytest.raises(KeyError):
        run_responses_agent(client, model="test-model", context={}, tool_specs=[], tools={})
