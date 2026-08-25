from behavior_engine import (
    AssetObservation,
    build_baseline,
    detect_behavior_changes,
    evaluate_observations,
)


def observation(**overrides: object) -> AssetObservation:
    value: dict[str, object] = {
        "observed_at": "2026-08-25T10:00:00+00:00",
        "hostname": "server-01",
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "manufacturer": "Example",
        "device_family": "server",
        "open_ports": (22, 443),
        "services": ("ssh", "https"),
        "criticality": "High",
        "exposure_score": 20,
    }
    value.update(overrides)
    return AssetObservation.from_mapping(value)


def test_baseline_requires_minimum_history():
    assert build_baseline([observation(), observation()]) is None
    baseline = build_baseline([observation(), observation(), observation()])
    assert baseline is not None
    assert baseline.stable_ports == (22, 443)
    assert baseline.stable_services == ("https", "ssh")


def test_new_port_is_explainable_and_deterministic():
    baseline = build_baseline([observation(), observation(), observation()])
    findings = detect_behavior_changes(
        baseline,
        observation(open_ports=(22, 443, 8080)),
    )
    assert [item.kind for item in findings] == ["new_port"]
    assert findings[0].severity == "Medium"
    assert "new_ports=8080" in findings[0].evidence


def test_identity_change_is_detected_without_payload_data():
    baseline = build_baseline([observation(), observation(), observation()])
    findings = detect_behavior_changes(
        baseline,
        observation(mac_address="11:22:33:44:55:66"),
    )
    assert [item.kind for item in findings] == ["identity_changed"]
    assert findings[0].confidence == "Medium"


def test_first_observation_has_no_anomaly():
    baseline, findings = evaluate_observations([observation()])
    assert baseline is None
    assert findings == ()


def test_service_and_exposure_changes_are_reported():
    history = [observation(exposure_score=10) for _ in range(5)]
    baseline, findings = evaluate_observations(
        history + [observation(services=("ssh", "https", "rdp"), exposure_score=50)]
    )
    assert baseline is not None
    kinds = {item.kind for item in findings}
    assert kinds == {"new_service", "exposure_shift"}
    assert all(item.confidence == "High" or item.confidence == "Medium" for item in findings)


def test_invalid_thresholds_fail_closed():
    try:
        build_baseline([observation()] * 3, port_persistence=0)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid persistence must fail")
