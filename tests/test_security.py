from security import classify_port_risk, validate_cidr, validate_target_ip


def test_private_ip_allowed():
    result = validate_target_ip("192.168.1.1")
    assert result.ok
    assert result.value == "192.168.1.1"


def test_public_ip_blocked():
    result = validate_target_ip("8.8.8.8")
    assert not result.ok


def test_local_ipv6_targets_allowed():
    ula = validate_target_ip("fd00::1")
    loopback = validate_target_ip("::1")
    link_local = validate_target_ip("fe80::10%eth0")

    assert ula.ok and ula.value == "fd00::1"
    assert loopback.ok and loopback.value == "::1"
    assert link_local.ok and link_local.value == "fe80::10%eth0"


def test_public_ipv6_target_blocked():
    result = validate_target_ip("2001:4860:4860::8888")
    assert not result.ok
    assert "local IPv6" in (result.error or "")


def test_ipv6_scope_restricted_to_link_local_targets():
    result = validate_target_ip("fd00::1%eth0")
    assert not result.ok
    assert "link-local" in (result.error or "")


def test_private_cidr_allowed():
    result = validate_cidr("192.168.1.0/24")
    assert result.ok


def test_public_or_mixed_cidr_blocked():
    result = validate_cidr("192.0.0.0/8")
    assert not result.ok


def test_ipv6_cidr_blocked():
    result = validate_cidr("fd00::/120")
    assert not result.ok


def test_large_network_blocked():
    result = validate_cidr("10.0.0.0/16")
    assert not result.ok


def test_risk_classification():
    assert classify_port_risk(23, True) == "High"
    assert classify_port_risk(22, True) == "Medium"
    assert classify_port_risk(443, False) == "None"
