from pathlib import Path


def test_traffic_explorer_surfaces_safe_application_protocol_insights() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    assert "Application insights" in javascript
    assert "traffic-application-insights" in javascript
    assert "protocol_events" in javascript
    assert "DNS query" in javascript
    assert "TLS server" in javascript
    assert "HTTP host" in javascript
    assert "buildPivotButton('Flow'" in javascript
    assert "slice(0, 200)" in javascript


def test_application_insight_ui_has_bounded_type_and_value_filters() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    assert "traffic-application-type-filter" in javascript
    assert "traffic-application-value-filter" in javascript
    assert "traffic-application-filter-state" in javascript
    assert "filterTrafficApplicationInsightRows" in javascript
    assert ".slice(0, 200)" in javascript
    assert "latestTrafficApplicationPayload" in javascript


def test_application_insight_filters_stay_scoped_to_selected_flow_payload() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")
    rows_function = javascript.split("function trafficApplicationInsightRows", 1)[-1]
    rows_function = rows_function.split("function installTrafficApplicationInsightsPanel", 1)[0]

    assert "payload?.flows" in rows_function
    assert "protocol_events" in rows_function
    assert "window.NetWatchApi" not in rows_function
    assert "/api/traffic/" not in rows_function


def test_application_insight_ui_does_not_add_sensitive_payload_fields() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")
    detail_function = javascript.lower().split("function applicationinsightdetail", 1)[-1]
    detail_function = detail_function.split("let latesttrafficapplicationpayload", 1)[0]

    assert "authorization" not in detail_function
    assert "cookie" not in detail_function
    assert "payload" not in detail_function
