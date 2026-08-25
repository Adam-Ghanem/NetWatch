from ai_analyst import assess_asset


def test_analyst_prioritizes_highest_severity():
    result = assess_asset(
        {"fingerprint": {"platform": "Android", "confidence": "High"}},
        [
            {"kind": "new_port", "severity": "medium"},
            {"kind": "identity_changed", "severity": "high"},
        ],
    )
    assert result.risk == "High"
    assert result.confidence == "High"
    assert "2 behavioral finding(s)" in result.summary
    assert result.recommended_action.startswith("Validate")


def test_analyst_does_not_invent_findings():
    result = assess_asset({"fingerprint": {"platform": "Linux"}}, [])
    assert result.risk == "Informational"
    assert result.evidence == ()
    assert "No behavioral findings" in result.summary
