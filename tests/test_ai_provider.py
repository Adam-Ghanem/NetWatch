from ai_provider import DisabledAIProvider


def test_disabled_provider_is_safe_and_deterministic():
    provider = DisabledAIProvider()
    assert "disabled" in provider.analyze({}).lower()
