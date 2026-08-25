from behavior_anomaly import BehaviorObservation, detect_behavior_anomalies, normalize_observation


def test_detects_new_sensitive_port_and_service():
    baseline = BehaviorObservation(
        "192.168.1.10", frozenset({80}), frozenset({"http"}), "Linux", 20
    )
    current = BehaviorObservation(
        "192.168.1.10", frozenset({22, 80}), frozenset({"http", "ssh"}), "Linux", 25
    )
    findings = detect_behavior_anomalies(baseline, current)
    assert {finding.kind for finding in findings} == {"new_ports", "new_services"}
    port_finding = next(f for f in findings if f.kind == "new_ports")
    assert port_finding.severity == "high"
    assert port_finding.confidence >= 0.9


def test_detects_identity_and_exposure_shift():
    baseline = BehaviorObservation(
        "10.0.0.5", frozenset({443}), frozenset({"https"}), "Windows", 10
    )
    current = BehaviorObservation("10.0.0.5", frozenset({443}), frozenset({"https"}), "Linux", 40)
    findings = detect_behavior_anomalies(baseline, current)
    assert {finding.kind for finding in findings} == {"identity_shift", "exposure_increase"}


def test_normalization_is_bounded_and_deterministic():
    observation = normalize_observation(
        {
            "ip_address": "10.0.0.8",
            "ports": [22, 0, 65536, "443"],
            "services": "SSH, HTTPS",
            "device_family": "Linux",
            "exposure_score": 999,
        }
    )
    assert observation.asset == "10.0.0.8"
    assert observation.open_ports == frozenset({22, 443})
    assert observation.services == frozenset({"ssh", "https"})
    assert observation.exposure_score == 100
