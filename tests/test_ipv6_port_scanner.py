import socket

import port_scanner


def test_ipv6_socket_target_uses_af_inet6():
    family, address = port_scanner._socket_target("fd00::25", 443)

    assert family == socket.AF_INET6
    assert address == ("fd00::25", 443, 0, 0)


def test_scoped_link_local_target_uses_interface_index(monkeypatch):
    monkeypatch.setattr(port_scanner.socket, "if_nametoindex", lambda name: 7)

    family, address = port_scanner._socket_target("fe80::10%eth0", 22)

    assert family == socket.AF_INET6
    assert address == ("fe80::10", 22, 0, 7)


def test_ipv4_socket_target_remains_compatible():
    family, address = port_scanner._socket_target("192.168.1.10", 80)

    assert family == socket.AF_INET
    assert address == ("192.168.1.10", 80)


def test_public_ipv6_scan_is_blocked_without_socket_activity(monkeypatch):
    def fail_socket(*args, **kwargs):
        raise AssertionError("socket activity must not occur for a blocked target")

    monkeypatch.setattr(port_scanner.socket, "socket", fail_socket)

    result = port_scanner.scan_ports("2001:4860:4860::8888")

    assert len(result) == 1
    assert result[0]["Status"] == "Blocked"
    assert "local IPv6" in result[0]["Recommendation"]
