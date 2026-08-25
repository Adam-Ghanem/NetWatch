import pytest

from ai_agent_loop import ToolCallLimitExceeded, run_agent_loop


def test_agent_loop_executes_registered_tool_then_finishes():
    calls = []

    def model(messages, tools):
        calls.append((messages, tools))
        if len(calls) == 1:
            return {"tool_calls": [{"name": "asset_history", "arguments": {"id": "a1"}}]}
        return {"answer": "history reviewed"}

    result = run_agent_loop(
        model, {"asset": "a1"}, {"asset_history": lambda args: {"id": args["id"], "events": []}}
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
