from __future__ import annotations

import pytest

from ai_advisor import (
    AIProviderError,
    api_key_is_usable,
    request_intelligence_brief,
    safety_configuration_is_usable,
)
from ai_anthropic import request_anthropic_intelligence_brief


VALID_KEY = "sk-test_project-key.with+safe/token=="
SAFETY_SECRET = "test-independent-safety-secret-with-enough-characters"
SUBJECT_ID = "deployment_subject_12345"
SNAPSHOT = {"privacy": {"deidentified": True}, "assets": {"total": 1}}


@pytest.mark.parametrize(
    "value",
    [
        "x" * 20 + "\r\nInjected: yes",
        "x" * 20 + "\n",
        "\n" + "x" * 20,
        "x" * 20 + "\t",
        "x" * 20 + "\t" + "y",
        "x" * 10 + " " + "y" * 10,
        "x" * 20 + "\x7f",
        "x" * 20 + "é",
    ],
)
def test_provider_key_rejects_whitespace_control_and_non_ascii(value):
    assert not api_key_is_usable(value)
    assert not safety_configuration_is_usable(
        api_key=value,
        safety_secret=SAFETY_SECRET,
        subject_id=SUBJECT_ID,
    )


def test_provider_key_accepts_printable_ascii_token_punctuation():
    assert api_key_is_usable(VALID_KEY)
    assert api_key_is_usable(f"  {VALID_KEY}  ")


@pytest.mark.parametrize(
    "provider_call",
    [request_intelligence_brief, request_anthropic_intelligence_brief],
)
@pytest.mark.parametrize(
    "key",
    [
        "x" * 20 + "\r\nInjected: yes",
        "x" * 20 + "\t" + "y",
        "x" * 20 + "\n",
        "x" * 20 + "\t",
    ],
)
def test_both_provider_adapters_reject_invalid_key_before_transport(provider_call, key):
    transport_called = False

    def forbidden_transport(*_args, **_kwargs):
        nonlocal transport_called
        transport_called = True
        raise AssertionError("invalid provider key must be rejected before transport")

    with pytest.raises(AIProviderError) as caught:
        if provider_call is request_intelligence_brief:
            provider_call(
                SNAPSHOT,
                api_key=key,
                safety_id="nw_test_identifier",
                opener=forbidden_transport,
            )
        else:
            provider_call(
                SNAPSHOT,
                api_key=key,
                safety_id="nw_test_identifier",
                model="claude-test-model",
                opener=forbidden_transport,
            )

    assert caught.value.code == "provider_not_configured"
    assert str(caught.value) == "The intelligence provider is not configured."
    assert not transport_called
