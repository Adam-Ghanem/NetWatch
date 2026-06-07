from network_tools import guess_gateway, network_profile


def test_network_profile_for_private_cidr():
    profile = network_profile("192.168.1.0/24")

    assert profile.scan_allowed
    assert profile.network_address == "192.168.1.0"
    assert profile.broadcast_address == "192.168.1.255"
    assert profile.netmask == "255.255.255.0"
    assert profile.usable_hosts == 254
    assert profile.first_hosts[0] == "192.168.1.1"


def test_guess_gateway_returns_first_host():
    assert guess_gateway("192.168.10.0/24") == "192.168.10.1"


def test_network_profile_rejects_public_cidr():
    profile = network_profile("8.8.8.0/24")

    assert not profile.scan_allowed
    assert profile.network_address == "-"
