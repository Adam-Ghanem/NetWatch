from alert_policy import should_alert


def test_high_alert_requires_evidence():
    assert should_alert({"severity": "high", "evidence": ["new port 443"]}) is True
    assert should_alert({"severity": "high", "evidence": []}) is False


def test_low_finding_is_suppressed_by_high_threshold():
    assert should_alert({"severity": "low", "evidence": ["hint"]}) is False


def test_critical_finding_alerts():
    assert should_alert({"severity": "critical", "evidence": ["identity changed"]}) is True
