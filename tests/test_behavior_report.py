from behavior_report import summarize_behavior


def test_summary_groups_findings_and_caps_risk():
    result = summarize_behavior([
        {"kind": "new_port", "severity": "high"},
        {"kind": "new_port", "severity": "medium"},
        {"kind": "identity_changed", "severity": "critical"},
    ])
    assert result["total"] == 3
    assert result["severity"]["critical"] == 1
    assert result["severity"]["high"] == 1
    assert result["by_kind"]["new_port"] == 2
    assert result["risk_score"] == 68


def test_empty_summary_is_deterministic():
    assert summarize_behavior([]) == {
        "total": 0,
        "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_kind": {},
        "risk_score": 0,
    }
