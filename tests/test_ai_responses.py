from types import SimpleNamespace

from ai_responses import extract_function_calls, response_tool_specs


def test_tool_specs_are_strict_and_closed():
    specs = response_tool_specs({"asset_snapshot": "Read collected asset evidence"})
    assert specs[0]["type"] == "function"
    assert specs[0]["strict"] is True
    assert specs[0]["parameters"]["additionalProperties"] is False


def test_function_calls_are_normalized():
    response = SimpleNamespace(output=[
        SimpleNamespace(type="message"),
        SimpleNamespace(type="function_call", name="asset_snapshot", call_id="c1", arguments='{"id":"a1"}'),
    ])
    assert extract_function_calls(response) == [{
        "name": "asset_snapshot", "call_id": "c1", "arguments": '{"id":"a1"}'
    }]
