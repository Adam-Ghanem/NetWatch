from pathlib import Path


def test_traffic_explorer_surfaces_bounded_flow_topology() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    assert "Traffic topology" in javascript
    assert "traffic-topology" in javascript
    assert "payload?.topology" in javascript
    assert "slice(0, 80)" in javascript
    assert "slice(0, 120)" in javascript
    assert "buildPivotButton('Investigate'" in javascript


def test_topology_ui_exposes_evidence_and_truncation_state() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")

    assert "traffic-topology-state" in javascript
    assert "device?.confidence" in javascript
    assert "device?.source" in javascript
    assert "topology.truncated" in javascript
    assert "Observed flow evidence only" in javascript


def test_topology_rendering_stays_scoped_to_selected_analysis_payload() -> None:
    javascript = Path("frontend/app.js").read_text(encoding="utf-8")
    topology_function = javascript.split("function renderTrafficTopology", 1)[-1]
    topology_function = topology_function.split("function installTrafficTopology", 1)[0]

    assert "payload?.topology" in topology_function
    assert "window.NetWatchApi" not in topology_function
    assert "/api/traffic/" not in topology_function
