from __future__ import annotations

import pytest

import flow_anomaly

def _flow(
    flow_id: str,
    source: str,
    destination: str,
    *,
    state: str = "established",
    originator_bytes: int = 500,
    responder_bytes: int = 500,
) -> dict[str, object]:
    return {
        "flow_id": flow_id,
        "protocol": "TCP",
        "originator": {"ip": source, "port": 50000},
        "responder": {"ip": destination, "port": 443},
        "tcp_state": state,
        "originator_bytes": originator_bytes,
        "responder_bytes": responder_bytes,
        "bytes": originator_bytes + responder_bytes,
    }


def test_detects_explainable_fanout_and_reset_burst_signals():
    flows = [
        _flow(f"fanout-{index}", "192.168.1.20", f"192.168.2.{index + 1}")
        for index in range(4)
    ]
    flows.extend(
        _flow(
            f"reset-{index}",
            "192.168.1.30",
            f"192.168.3.{index + 1}",
            state="reset",
        )
        for index in range(3)
    )

    policy = flow_anomaly.FlowAnomalyPolicy(
        high_fanout_threshold=4,
        reset_burst_threshold=3,
        byte_asymmetry_ratio=50.0,
    )
    findings = flow_anomaly.analyze_flow_anomalies(flows, policy=policy)

    assert [finding["signal"] for finding in findings] == [
        "high_fanout",
        "reset_burst",
    ]
    assert findings[0]["entity"] == "192.168.1.20"
    assert findings[0]["observed"] == 4
    assert findings[0]["threshold"] == 4
    assert findings[1]["entity"] == "192.168.1.30"
    assert findings[1]["observed"] == 3
    assert all(finding["explanation"] for finding in findings)


def test_detects_material_byte_asymmetry_but_ignores_tiny_flows():
    flows = [
        _flow(
            "large-asymmetry",
            "192.168.1.40",
            "192.168.1.1",
            originator_bytes=5_000,
            responder_bytes=100,
        ),
        _flow(
            "tiny-asymmetry",
            "192.168.1.41",
            "192.168.1.1",
            originator_bytes=50,
            responder_bytes=1,
        ),
    ]
    policy = flow_anomaly.FlowAnomalyPolicy(
        high_fanout_threshold=20,
        reset_burst_threshold=10,
        byte_asymmetry_ratio=20.0,
        byte_asymmetry_min_bytes=1_000,
    )

    findings = flow_anomaly.analyze_flow_anomalies(flows, policy=policy)

    assert len(findings) == 1
    assert findings[0]["signal"] == "byte_asymmetry"
    assert findings[0]["flow_ids"] == ["large-asymmetry"]
    assert findings[0]["observed"] == 50.0
    assert findings[0]["threshold"] == 20.0


def test_analysis_is_bounded_and_policy_fails_closed():
    policy = flow_anomaly.FlowAnomalyPolicy(max_flows=2)
    flows = [
        _flow("one", "192.168.1.10", "192.168.1.1"),
        _flow("two", "192.168.1.11", "192.168.1.1"),
        _flow("three", "192.168.1.12", "192.168.1.1"),
    ]

    with pytest.raises(ValueError, match="at most 2 flows"):
        flow_anomaly.analyze_flow_anomalies(flows, policy=policy)

    with pytest.raises(ValueError, match="Fan-out threshold"):
        flow_anomaly.FlowAnomalyPolicy(high_fanout_threshold=1).validate()
