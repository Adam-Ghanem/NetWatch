from risk_engine import exposure_level, summarize_exposure, top_recommendations


def test_exposure_level_thresholds():
    assert exposure_level(0) == "Clean"
    assert exposure_level(1) == "Low"
    assert exposure_level(5) == "Medium"
    assert exposure_level(12) == "High"


def test_summarize_exposure_scores_open_ports_only():
    rows = [
        {"Port": 22, "Status": "Open", "Risk": "Medium"},
        {"Port": 3389, "Status": "Open", "Risk": "High"},
        {"Port": 443, "Status": "Closed", "Risk": "High"},
    ]

    summary = summarize_exposure(rows)

    assert summary.checked == 3
    assert summary.open_ports == 2
    assert summary.high == 1
    assert summary.medium == 1
    assert summary.score == 6
    assert summary.level == "Medium"


def test_top_recommendations_prioritizes_high_risk():
    rows = [
        {"Port": 80, "Status": "Open", "Risk": "Medium"},
        {"Port": 3389, "Status": "Open", "Risk": "High"},
        {"Port": 443, "Status": "Closed", "Risk": "None"},
    ]

    top = top_recommendations(rows, limit=1)

    assert top[0]["Port"] == 3389


def test_high_risk_findings_raise_the_minimum_exposure_level():
    one_high = summarize_exposure([{"Status": "Open", "Risk": "High"}])
    two_high = summarize_exposure(
        [
            {"Status": "Open", "Risk": "High"},
            {"Status": "Open", "Risk": "High"},
        ]
    )

    assert one_high.level == "Medium"
    assert two_high.level == "High"
