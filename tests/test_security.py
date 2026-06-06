from security import classify_port_risk, validate_cidr, validate_target_ip


def test_private_ip_allowed():
    result = validate_target_ip("192.168.1.1")
    assert result.ok
    assert result.value == "192.168.1.1"


def test_public_ip_blocked():
    result = validate_target_ip("8.8.8.8")
    assert not result.ok


def test_private_cidr_allowed():
    result = validate_cidr("192.168.1.0/24")
    assert result.ok


def test_large_network_blocked():
    result = validate_cidr("10.0.0.0/16")
    assert not result.ok


def test_risk_classification():
    assert classify_port_risk(23, True) == "High"
    assert classify_port_risk(22, True) == "Medium"
    assert classify_port_risk(443, False) == "None"
