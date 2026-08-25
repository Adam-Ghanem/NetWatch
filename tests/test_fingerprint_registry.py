from fingerprint_registry import matching_rules


def test_registry_matches_multiple_platform_signals():
    rules = matching_rules("Google Android Pixel")
    assert any(rule.platform == "Android" for rule in rules)


def test_registry_is_case_insensitive():
    rules = matching_rules("APPLE IPHONE")
    assert any(rule.platform == "iOS/iPadOS" for rule in rules)


def test_registry_returns_empty_for_unknown():
    assert matching_rules("mystery-device") == ()
