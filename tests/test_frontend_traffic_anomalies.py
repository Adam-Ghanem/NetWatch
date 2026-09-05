from pathlib import Path


def test_traffic_explorer_surfaces_bounded_explainable_anomalies() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    assert "Explainable anomalies" in javascript
    assert "traffic-anomaly-findings" in javascript
    assert "payload?.anomalies" in javascript
    assert "slice(0, 100)" in javascript
    assert "Observed / threshold" in javascript
    assert "Confidence" in javascript
    assert "Evidence" in javascript
    assert "Explanation" in javascript
    assert "buildPivotButton('Investigate'" in javascript


def test_anomaly_surface_supports_local_severity_and_evidence_search() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    assert "traffic-anomaly-severity-filter" in javascript
    assert "traffic-anomaly-value-filter" in javascript
    assert "traffic-anomaly-filter-state" in javascript
    assert "selected-flow anomalies" in javascript
    assert "No anomaly filter active." in javascript


def test_anomaly_rendering_stays_scoped_to_selected_analysis_payload() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")
    anomaly_function = javascript.split("function renderTrafficAnomalies", 1)[-1]
    anomaly_function = anomaly_function.split("function installTrafficAnomalies", 1)[0]

    assert "payload?.anomalies" in anomaly_function
    assert "payload?.flows" in anomaly_function
    assert "window.NetWatchApi" not in anomaly_function
    assert "/api/traffic/" not in anomaly_function
