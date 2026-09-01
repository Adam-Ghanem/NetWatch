from __future__ import annotations

import pytest

import flow_change_intelligence


def _flow(
    flow_id: str,
    source: str,
    destination: str,
    *,
    destination_port: int = 443,
    service: str = "https",
    protocol: str = "TCP",
    byte_count: int = 2_048,
) -> dict[str, object]:
    return {
        "flow_id": flow_id,
        "protocol": protocol,
        "service": service,
        "originator": {"ip": source, "port": 50_000},
        "responder": {"ip": destination, "port": destination_port},
        "packets": 8,
        "bytes": byte_count,
        "payload": "must-never-escape",
    }


def test_detects_new_endpoint_and_new_service_exposure():
    previous = [
        _flow("old-web", "192.168.1.10", "192.168.1.20"),
    ]
    current = [
        _flow("same-web", "192.168.1.10", "192.168.1.20"),
        _flow(
            "new-ssh",
            "192.168.1.10",
            "192.168.1.30",
            destination_port=22,
            service="ssh",
        ),
    ]

    findings = flow_change_intelligence.compare_flow_snapshots(previous, current)

    assert [finding["change"] for finding in findings] == [
        "new_endpoint",
        "new_service",
    ]
    assert findings[0]["entity"] == "192.168.1.30"
    assert findings[1]["entity"] == "192.168.1.30:22/tcp"
    assert findings[1]["service"] == "ssh"
    assert findings[1]["flow_ids"] == ["new-ssh"]
    assert all(finding["explanation"] for finding in findings)


def test_detects_missing_endpoint_and_service():
    previous = [
        _flow(
            "old-ssh",
            "192.168.1.10",
            "192.168.1.30",
            destination_port=22,
            service="ssh",
        )
    ]
    current: list[dict[str, object]] = []

    findings = flow_change_intelligence.compare_flow_snapshots(previous, current)

    assert [finding["change"] for finding in findings] == [
        "missing_endpoint",
        "missing_endpoint",
        "missing_service",
    ]
    assert {finding["entity"] for finding in findings[:2]} == {
        "192.168.1.10",
        "192.168.1.30",
    }
    assert findings[2]["entity"] == "192.168.1.30:22/tcp"
    assert findings[2]["flow_ids"] == ["old-ssh"]


def test_service_identity_includes_port_and_protocol():
    previous = [
        _flow(
            "old-dns",
            "192.168.1.10",
            "192.168.1.53",
            destination_port=53,
            service="dns",
            protocol="UDP",
        )
    ]
    current = [
        _flow(
            "new-dns",
            "192.168.1.10",
            "192.168.1.53",
            destination_port=5353,
            service="dns",
            protocol="UDP",
        )
    ]

    findings = flow_change_intelligence.compare_flow_snapshots(previous, current)

    service_findings = [item for item in findings if item["change"] == "new_service"]
    assert len(service_findings) == 1
    assert service_findings[0]["entity"] == "192.168.1.53:5353/udp"
    assert service_findings[0]["service"] == "dns"


def test_detects_material_service_traffic_volume_drift():
    previous = [
        _flow(
            "old-web",
            "192.168.1.10",
            "192.168.1.20",
            byte_count=8_192,
        )
    ]
    current = [
        _flow(
            "new-web",
            "192.168.1.10",
            "192.168.1.20",
            byte_count=32_768,
        )
    ]

    findings = flow_change_intelligence.compare_flow_snapshots(previous, current)

    assert [finding["change"] for finding in findings] == ["traffic_volume_increase"]
    finding = findings[0]
    assert finding["entity"] == "192.168.1.20:443/tcp"
    assert finding["baseline_bytes"] == 8_192
    assert finding["current_bytes"] == 32_768
    assert finding["ratio"] == 4.0
    assert finding["flow_ids"] == ["new-web"]


def test_ignores_small_or_immaterial_volume_changes():
    small_previous = [_flow("old", "192.168.1.10", "192.168.1.20", byte_count=512)]
    small_current = [_flow("new", "192.168.1.10", "192.168.1.20", byte_count=2_048)]
    assert not flow_change_intelligence.compare_flow_snapshots(small_previous, small_current)

    steady_previous = [_flow("old", "192.168.1.10", "192.168.1.20", byte_count=10_000)]
    steady_current = [_flow("new", "192.168.1.10", "192.168.1.20", byte_count=20_000)]
    assert not flow_change_intelligence.compare_flow_snapshots(steady_previous, steady_current)


def test_comparison_is_bounded_and_never_retains_payloads():
    policy = flow_change_intelligence.FlowChangePolicy(max_flows_per_snapshot=1)
    flows = [
        _flow("one", "192.168.1.10", "192.168.1.20"),
        _flow("two", "192.168.1.10", "192.168.1.21"),
    ]

    with pytest.raises(ValueError, match="at most 1 flow"):
        flow_change_intelligence.compare_flow_snapshots([], flows, policy=policy)

    findings = flow_change_intelligence.compare_flow_snapshots([], flows[:1], policy=policy)
    assert findings
    assert "payload" not in repr(findings).lower()

    with pytest.raises(ValueError, match="between 1 and 5000"):
        flow_change_intelligence.FlowChangePolicy(max_flows_per_snapshot=0).validate()
    with pytest.raises(ValueError, match="ratio threshold"):
        flow_change_intelligence.FlowChangePolicy(volume_ratio_threshold=1.0).validate()
