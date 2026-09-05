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


def test_application_insight_ui_does_not_add_sensitive_payload_fields() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")
    detail_function = javascript.lower().split("function applicationinsightdetail", 1)[-1]
    detail_function = detail_function.split("function", 1)[0]

    assert "authorization" not in detail_function
    assert "cookie" not in detail_function
    assert "payload" not in detail_function
