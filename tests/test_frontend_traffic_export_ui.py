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


def test_traffic_explorer_has_bounded_offline_capture_controls() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    assert "function offlineAnalysisUrl" in javascript
    assert "function analyzeOfflineCapture" in javascript
    assert "function installOfflineCaptureControls" in javascript
    assert "function buildOfflineLimitControl" in javascript
    assert "traffic-offline-file" in javascript
    assert "traffic-offline-authorized" in javascript
    assert "traffic-offline-packet-limit" in javascript
    assert "traffic-offline-flow-limit" in javascript
    assert "'/api/traffic/offline/analyze?'" not in javascript
    assert "`/api/traffic/offline/analyze?${params.toString()}`" in javascript
    assert "headers: { 'Content-Type': 'application/octet-stream' }" in javascript
    assert "body: file" in javascript
    assert "renderTrafficCapture(payload)" in javascript
    assert "Live sensor packet privileges are not required." in javascript
    assert "Raw payload bytes were not retained." in javascript
    assert "innerHTML" not in javascript


def test_traffic_explorer_has_bounded_offline_flow_download_controls() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    assert "function offlineExportUrl" in javascript
    assert "function downloadOfflineFlows" in javascript
    assert "traffic-offline-export-format" in javascript
    assert "traffic-offline-export" in javascript
    assert "`/api/traffic/offline/export.${exportFormat}?${params.toString()}`" in javascript
    assert "headers: { 'Content-Type': 'application/octet-stream' }" in javascript
    assert "body: file" in javascript
    assert "Export offline flows" in javascript
    assert "Offline ${exportFormat.toUpperCase()} flow export downloaded." in javascript
    assert "innerHTML" not in javascript


def test_traffic_explorer_surfaces_flow_conversation_and_endpoint_pivots() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    assert "function installTrafficFlowPivotPanels" in javascript
    assert "traffic-flow-conversations" in javascript
    assert "traffic-flow-endpoints" in javascript
    assert "function renderTrafficFlowPivots" in javascript
    assert "function applyTrafficFlowPivot" in javascript
    assert "payload.conversation_count" in javascript
    assert "payload.endpoint_count" in javascript
    assert "traffic-ip" in javascript
    assert "traffic-port" in javascript
    assert "traffic-protocol" in javascript
    assert "Limit next capture/analysis to this flow pivot" in javascript
    assert "innerHTML" not in javascript
