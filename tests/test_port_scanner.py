import socket

import pytest

import port_scanner


class FakeSocket:
    def __init__(self, family, kind, calls):
        self.family = family
        self.kind = kind
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, timeout):
        self.calls.append(("timeout", timeout))

    def connect_ex(self, endpoint):
        self.calls.append(("connect", self.family, endpoint))
        return 0


def test_ipv6_scan_uses_ipv6_socket(monkeypatch):
    calls = []
    monkeypatch.setattr(port_scanner, "COMMON_PORTS", {443: "HTTPS"})
    monkeypatch.setattr(
        port_scanner.socket,
        "socket",
        lambda family, kind: FakeSocket(family, kind, calls),
    )

    rows = port_scanner.scan_ports("fd00::10")

    assert rows[0]["Status"] == "Open"
    assert ("connect", socket.AF_INET6, ("fd00::10", 443, 0, 0)) in calls


def test_timeout_must_be_positive():
    with pytest.raises(ValueError, match="greater than zero"):
        port_scanner.scan_ports("192.168.1.1", timeout=0)
