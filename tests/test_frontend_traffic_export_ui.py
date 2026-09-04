from pathlib import Path


def test_traffic_explorer_has_flow_export_controls() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")
    core = Path("frontend/app-core.js").read_text(encoding="utf-8")

    assert "script.src = '/app-core.js'" in javascript
    assert "formatSelect.id = 'traffic-export-format'" in javascript
    assert "exportButton.id = 'traffic-export'" in javascript
    assert "exportButton.dataset.captureControl = ''" in javascript
    assert "function trafficCaptureRequest" in javascript
    assert "function downloadTrafficFlows" in javascript
    assert "`/api/traffic/capture/export.${exportFormat}`" in javascript
    assert "method: 'POST'" in javascript
    assert "body: JSON.stringify(trafficCaptureRequest())" in javascript
    assert "Capture & export flows" in javascript
    assert "renderTrafficCapture" in core
