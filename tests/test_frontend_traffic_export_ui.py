from pathlib import Path


def test_traffic_explorer_has_flow_export_controls() -> None:
    html = Path("frontend/index.html").read_text(encoding="utf-8")
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    # fmt: off
    assert "id=\"traffic-export-format\"" in html
    assert "id=\"traffic-export\"" in html
    assert "data-capture-control" in html
    assert "function trafficCaptureRequest" in javascript
    assert "function downloadTrafficFlows" in javascript
    assert "`/api/traffic/capture/export.${exportFormat}`" in javascript
    assert "method: 'POST'" in javascript
    assert "body: JSON.stringify(trafficCaptureRequest())" in javascript
    assert "Capture & export" in html
    # fmt: on
