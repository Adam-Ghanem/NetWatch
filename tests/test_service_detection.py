import socket

import port_scanner


class _GreetingSocket:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.timeouts = []
        self.recv_sizes = []

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, size):
        self.recv_sizes.append(size)
        return self.payload


def test_ssh_greeting_extracts_product_and_version_without_returning_raw_banner():
    sock = _GreetingSocket(b"SSH-2.0-OpenSSH_9.8p1 host.internal.example\r\n")

    evidence = port_scanner._ssh_service_evidence(sock, timeout=2.0)

    assert evidence == {
        "Service Detection": "SSH greeting",
        "Service Product": "OpenSSH",
        "Service Version": "9.8p1",
        "Service Confidence": "High",
    }
    assert sock.recv_sizes == [256]
    assert sock.timeouts == [0.25]
    assert "host.internal.example" not in str(evidence)


def test_ssh_greeting_falls_back_when_identification_line_is_missing():
    sock = _GreetingSocket(b"not-an-ssh-identification\r\n")

    evidence = port_scanner._ssh_service_evidence(sock, timeout=0.1)

    assert evidence == {
        "Service Detection": "Port catalog",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Low",
    }
    assert sock.recv_sizes == [256]
    assert sock.timeouts == [0.1]


def test_ssh_greeting_timeout_is_non_fatal():
    class TimeoutSocket(_GreetingSocket):
        def recv(self, size):
            self.recv_sizes.append(size)
            raise socket.timeout()

    sock = TimeoutSocket(b"")

    evidence = port_scanner._ssh_service_evidence(sock, timeout=1.0)

    assert evidence["Service Detection"] == "Port catalog"
    assert evidence["Service Confidence"] == "Low"
