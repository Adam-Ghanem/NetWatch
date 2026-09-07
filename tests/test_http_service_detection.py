import socket
from typing import cast

import port_scanner


class _HttpSocket:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.timeouts: list[float] = []
        self.recv_sizes: list[int] = []
        self.sent: list[bytes] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def sendall(self, payload: bytes) -> None:
        self.sent.append(payload)

    def recv(self, size: int) -> bytes:
        self.recv_sizes.append(size)
        return self.payload


def test_http_probe_extracts_allowlisted_server_product_and_version() -> None:
    sock = _HttpSocket(
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\n"
        b"X-Internal-Node: app-07.private.example\r\n\r\n"
    )

    evidence = port_scanner._http_service_evidence(cast(socket.socket, sock), timeout=2.0)

    assert evidence == {
        "Service Detection": "HTTP Server header",
        "Service Product": "nginx",
        "Service Version": "1.26.2",
        "Service Confidence": "High",
    }
    assert sock.recv_sizes == [1024]
    assert sock.timeouts == [0.35]
    assert sock.sent == [b"HEAD / HTTP/1.0\r\nHost: netwatch.local\r\nConnection: close\r\n\r\n"]
    assert "app-07.private.example" not in str(evidence)


def test_http_probe_does_not_claim_unknown_server_product() -> None:
    sock = _HttpSocket(b"HTTP/1.0 200 OK\r\nServer: PrivateEdge/2026.9\r\n\r\n")

    evidence = port_scanner._http_service_evidence(cast(socket.socket, sock), timeout=0.1)

    assert evidence == {
        "Service Detection": "HTTP response",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Medium",
    }
    assert sock.timeouts == [0.1]


def test_http_probe_falls_back_for_non_http_response() -> None:
    sock = _HttpSocket(b"SSH-2.0-OpenSSH_9.8\r\n")

    evidence = port_scanner._http_service_evidence(cast(socket.socket, sock), timeout=1.0)

    assert evidence == {
        "Service Detection": "Port catalog",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Low",
    }


def test_http_probe_timeout_is_non_fatal() -> None:
    class TimeoutSocket(_HttpSocket):
        def recv(self, size: int) -> bytes:
            self.recv_sizes.append(size)
            raise socket.timeout()

    sock = TimeoutSocket(b"")

    evidence = port_scanner._http_service_evidence(cast(socket.socket, sock), timeout=1.0)

    assert evidence["Service Detection"] == "Port catalog"
    assert evidence["Service Confidence"] == "Low"
