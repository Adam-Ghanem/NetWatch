import socket

import pytest

import udp_service_scanner


class FakeDatagramSocket:
    def __init__(self, response=b"", error=None):
        self.response = response
        self.error = error
        self.timeout = None
        self.connected_to = None
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.connected_to = address
        if isinstance(self.error, ConnectionRefusedError):
            raise self.error

    def send(self, payload):
        self.sent.append(payload)
        return len(payload)

    def recv(self, size):
        if self.error:
            raise self.error
        return self.response[:size]


def _factory(sock):
    def make_socket(*_args, **_kwargs):
        return sock

    return make_socket


def test_dns_response_marks_service_open_and_retains_only_metadata():
    response = b"\x4e\x57\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    sock = FakeDatagramSocket(response=response)

    rows = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        timeout=0.2,
        socket_factory=_factory(sock),
    )

    assert len(rows) == 1
    assert rows[0] == {
        "Port": 53,
        "Protocol": "UDP",
        "Service": "DNS",
        "Status": "Open",
        "Response Time (ms)": pytest.approx(rows[0]["Response Time (ms)"], abs=0.01),
        "Service Detection": "DNS response",
        "Service Product": "DNS",
        "Service Version": "",
        "Service Confidence": "High",
    }
    assert 0 <= rows[0]["Response Time (ms)"] <= 1000
    assert len(sock.sent) == 1
    assert len(sock.sent[0]) == 17
    assert sock.timeout == 0.2


def test_timeout_is_reported_as_open_filtered_without_retry():
    sock = FakeDatagramSocket(error=socket.timeout())

    rows = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(sock),
    )

    assert rows[0]["Status"] == "Open|Filtered"
    assert rows[0]["Service Detection"] == "No UDP response"
    assert rows[0]["Service Confidence"] == "Low"
    assert len(sock.sent) == 1


def test_connection_refused_is_reported_closed():
    sock = FakeDatagramSocket(error=ConnectionRefusedError())

    rows = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(sock),
    )

    assert rows[0]["Status"] == "Closed"
    assert rows[0]["Service Detection"] == "ICMP/OS refusal"


def test_ntp_response_extracts_protocol_version_only():
    response = bytes([0x24]) + (b"\x00" * 47)  # LI=0, VN=4, mode=4 (server)
    sock = FakeDatagramSocket(response=response)

    rows = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("ntp",),
        socket_factory=_factory(sock),
    )

    assert rows[0]["Port"] == 123
    assert rows[0]["Status"] == "Open"
    assert rows[0]["Service Detection"] == "NTP response"
    assert rows[0]["Service Product"] == "NTP"
    assert rows[0]["Service Version"] == "v4"
    assert len(sock.sent) == 1
    assert len(sock.sent[0]) == 48


def test_invalid_response_does_not_claim_service_open():
    sock = FakeDatagramSocket(response=b"not-a-dns-response")

    rows = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(sock),
    )

    assert rows[0]["Status"] == "Open|Filtered"
    assert rows[0]["Service Detection"] == "Unexpected UDP response"
    assert rows[0]["Service Confidence"] == "Low"


def test_unknown_service_profile_is_rejected_before_network_activity():
    called = False

    def factory(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("socket should not be created")

    with pytest.raises(ValueError, match="Unsupported UDP service profile"):
        udp_service_scanner.scan_udp_services(
            "192.168.1.10",
            services=("snmp",),
            socket_factory=factory,
        )

    assert called is False


def test_timeout_is_tightly_bounded():
    with pytest.raises(ValueError, match="between 0.05 and 1.0 seconds"):
        udp_service_scanner.scan_udp_services("192.168.1.10", timeout=2.0)
