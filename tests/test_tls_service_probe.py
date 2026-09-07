import hashlib
import socket
import ssl
from typing import Any, cast

import port_scanner
import tls_service_probe


class _ConnectedSocket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)


class _TlsSocket:
    def __init__(
        self,
        certificate: bytes = b"certificate-bytes",
        alpn: str | None = "h2",
    ) -> None:
        self.certificate = certificate
        self.alpn = alpn

    def __enter__(self) -> "_TlsSocket":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def version(self) -> str:
        return "TLSv1.3"

    def cipher(self) -> tuple[str, str, int]:
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def selected_alpn_protocol(self) -> str | None:
        return self.alpn

    def getpeercert(self, *, binary_form: bool = False) -> bytes:
        assert binary_form is True
        return self.certificate


class _Context:
    def __init__(self, protocol: int) -> None:
        assert protocol == ssl.PROTOCOL_TLS_CLIENT
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED
        self.server_hostname: str | None = "unexpected"
        self.alpn_protocols: list[str] = []

    def set_alpn_protocols(self, protocols: list[str]) -> None:
        self.alpn_protocols = protocols

    def wrap_socket(
        self,
        sock: socket.socket,
        *,
        server_hostname: str | None = None,
    ) -> _TlsSocket:
        self.server_hostname = server_hostname
        return _TlsSocket()


def test_tls_probe_returns_bounded_handshake_metadata() -> None:
    sock = _ConnectedSocket()
    contexts: list[_Context] = []

    def context_factory(protocol: int) -> _Context:
        context = _Context(protocol)
        contexts.append(context)
        return context

    evidence = tls_service_probe.probe_tls_service(
        cast(socket.socket, sock),
        "192.168.1.20",
        timeout=2.0,
        context_factory=context_factory,
    )

    assert evidence == {
        "Service Detection": "TLS handshake",
        "Service Product": "TLS",
        "Service Version": "TLSv1.3",
        "Service Confidence": "High",
        "TLS Protocol": "TLSv1.3",
        "TLS Cipher": "TLS_AES_256_GCM_SHA384",
        "TLS ALPN": "h2",
        "TLS Certificate SHA256": hashlib.sha256(b"certificate-bytes").hexdigest(),
    }
    assert sock.timeouts == [0.5]
    assert contexts[0].check_hostname is False
    assert contexts[0].verify_mode == ssl.CERT_NONE
    assert contexts[0].server_hostname is None
    assert contexts[0].alpn_protocols == ["h2", "http/1.1"]
    assert "certificate-bytes" not in str(evidence)


def test_tls_probe_records_empty_alpn_when_server_does_not_negotiate_one() -> None:
    class NoAlpnContext(_Context):
        def wrap_socket(
            self,
            sock: socket.socket,
            *,
            server_hostname: str | None = None,
        ) -> _TlsSocket:
            self.server_hostname = server_hostname
            return _TlsSocket(alpn=None)

    evidence = tls_service_probe.probe_tls_service(
        cast(socket.socket, _ConnectedSocket()),
        "192.168.1.20",
        timeout=1.0,
        context_factory=NoAlpnContext,
    )

    assert evidence["TLS ALPN"] == ""
    assert evidence["TLS Protocol"] == "TLSv1.3"


def test_tls_probe_failure_falls_back_without_raising() -> None:
    class FailingContext(_Context):
        def wrap_socket(
            self,
            sock: socket.socket,
            *,
            server_hostname: str | None = None,
        ) -> _TlsSocket:
            raise ssl.SSLError("handshake failed")

    evidence = tls_service_probe.probe_tls_service(
        cast(socket.socket, _ConnectedSocket()),
        "192.168.1.20",
        timeout=0.1,
        context_factory=FailingContext,
    )

    assert evidence == {
        "Service Detection": "Port catalog",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Low",
    }


def test_tls_probe_rejects_oversized_certificate_body() -> None:
    class LargeCertificateContext(_Context):
        def wrap_socket(
            self,
            sock: socket.socket,
            *,
            server_hostname: str | None = None,
        ) -> _TlsSocket:
            return _TlsSocket(b"x" * (64 * 1024 + 1))

    evidence = tls_service_probe.probe_tls_service(
        cast(socket.socket, _ConnectedSocket()),
        "192.168.1.20",
        timeout=1.0,
        context_factory=LargeCertificateContext,
    )

    assert evidence["TLS Certificate SHA256"] == ""
    assert evidence["TLS Protocol"] == "TLSv1.3"


def test_https_scan_routes_open_port_to_tls_probe(monkeypatch: Any) -> None:
    class ScannerSocket:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self.timeout = 0.0

        def __enter__(self) -> "ScannerSocket":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def settimeout(self, value: float) -> None:
            self.timeout = value

        def connect_ex(self, address: tuple[object, ...]) -> int:
            return 0

    monkeypatch.setattr(port_scanner.socket, "socket", ScannerSocket)
    monkeypatch.setattr(
        port_scanner,
        "probe_tls_service",
        lambda sock, target, timeout: {
            "Service Detection": "TLS handshake",
            "Service Product": "TLS",
            "Service Version": "TLSv1.3",
            "Service Confidence": "High",
            "TLS Protocol": "TLSv1.3",
            "TLS Cipher": "TLS_AES_128_GCM_SHA256",
            "TLS ALPN": "h2",
            "TLS Certificate SHA256": "abc123",
        },
    )

    result = port_scanner._scan_one_port("192.168.1.20", 443, "HTTPS", 1.0)

    assert result["Status"] == "Open"
    assert result["Service Detection"] == "TLS handshake"
    assert result["TLS Protocol"] == "TLSv1.3"
    assert result["TLS Cipher"] == "TLS_AES_128_GCM_SHA256"
    assert result["TLS ALPN"] == "h2"
