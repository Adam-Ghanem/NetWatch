import socket
from typing import cast

import port_scanner


class _GreetingSocket:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.timeouts: list[float] = []
        self.recv_sizes: list[int] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def recv(self, size: int) -> bytes:
        self.recv_sizes.append(size)
        return self.payload


def test_ssh_greeting_extracts_product_and_version_without_returning_raw_banner() -> None:
    sock = _GreetingSocket(b"SSH-2.0-OpenSSH_9.8p1 host.internal.example\r\n")

    evidence = port_scanner._ssh_service_evidence(cast(socket.socket, sock), timeout=2.0)

    assert evidence == {
        "Service Detection": "SSH greeting",
        "Service Product": "OpenSSH",
        "Service Version": "9.8p1",
        "Service Confidence": "High",
    }
    assert sock.recv_sizes == [256]
    assert sock.timeouts == [0.25]
    assert "host.internal.example" not in str(evidence)


def test_ssh_greeting_falls_back_when_identification_line_is_missing() -> None:
    sock = _GreetingSocket(b"not-an-ssh-identification\r\n")

    evidence = port_scanner._ssh_service_evidence(cast(socket.socket, sock), timeout=0.1)

    assert evidence == {
        "Service Detection": "Port catalog",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Low",
    }
    assert sock.recv_sizes == [256]
    assert sock.timeouts == [0.1]


def test_ssh_greeting_timeout_is_non_fatal() -> None:
    class TimeoutSocket(_GreetingSocket):
        def recv(self, size: int) -> bytes:
            self.recv_sizes.append(size)
            raise socket.timeout()

    sock = TimeoutSocket(b"")

    evidence = port_scanner._ssh_service_evidence(cast(socket.socket, sock), timeout=1.0)

    assert evidence["Service Detection"] == "Port catalog"
    assert evidence["Service Confidence"] == "Low"


def test_ftp_greeting_extracts_known_product_version_without_retaining_hostname() -> None:
    sock = _GreetingSocket(b"220 edge-gw.internal ProFTPD 1.3.8 Server ready\r\n")

    evidence = port_scanner._ftp_service_evidence(cast(socket.socket, sock), timeout=2.0)

    assert evidence == {
        "Service Detection": "FTP greeting",
        "Service Product": "ProFTPD",
        "Service Version": "1.3.8",
        "Service Confidence": "High",
    }
    assert sock.recv_sizes == [256]
    assert sock.timeouts == [0.25]
    assert "edge-gw.internal" not in str(evidence)


def test_ftp_greeting_recognizes_vsftpd_without_claiming_missing_version() -> None:
    sock = _GreetingSocket(b"220 (vsFTPd 3.0.5)\r\n")

    evidence = port_scanner._ftp_service_evidence(cast(socket.socket, sock), timeout=0.1)

    assert evidence == {
        "Service Detection": "FTP greeting",
        "Service Product": "vsftpd",
        "Service Version": "3.0.5",
        "Service Confidence": "High",
    }
    assert sock.recv_sizes == [256]
    assert sock.timeouts == [0.1]


def test_ftp_greeting_falls_back_for_unrecognized_or_malformed_banner() -> None:
    sock = _GreetingSocket(b"220 storage.internal FTP service ready\r\n")

    evidence = port_scanner._ftp_service_evidence(cast(socket.socket, sock), timeout=1.0)

    assert evidence == {
        "Service Detection": "FTP greeting",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Medium",
    }
    assert "storage.internal" not in str(evidence)


def test_smtp_greeting_extracts_postfix_without_retaining_hostname() -> None:
    sock = _GreetingSocket(b"220 mail.internal.example ESMTP Postfix 3.9.1\r\n")

    evidence = port_scanner._smtp_service_evidence(cast(socket.socket, sock), timeout=2.0)

    assert evidence == {
        "Service Detection": "SMTP greeting",
        "Service Product": "Postfix",
        "Service Version": "3.9.1",
        "Service Confidence": "High",
    }
    assert sock.recv_sizes == [256]
    assert sock.timeouts == [0.25]
    assert "mail.internal.example" not in str(evidence)


def test_smtp_greeting_recognizes_exim_and_bounds_unknown_product_claims() -> None:
    exim = _GreetingSocket(b"220 mx.example ESMTP Exim 4.98 Tue, 06 Sep 2026 16:00:00 +0100\r\n")
    unknown = _GreetingSocket(b"220 private-mx.internal ESMTP ready\r\n")

    exim_evidence = port_scanner._smtp_service_evidence(cast(socket.socket, exim), timeout=0.1)
    unknown_evidence = port_scanner._smtp_service_evidence(
        cast(socket.socket, unknown), timeout=0.1
    )

    assert exim_evidence == {
        "Service Detection": "SMTP greeting",
        "Service Product": "Exim",
        "Service Version": "4.98",
        "Service Confidence": "High",
    }
    assert unknown_evidence == {
        "Service Detection": "SMTP greeting",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Medium",
    }
    assert "private-mx.internal" not in str(unknown_evidence)


def test_smtp_greeting_falls_back_when_server_first_banner_is_not_smtp() -> None:
    sock = _GreetingSocket(b"HTTP/1.1 200 OK\r\n")

    evidence = port_scanner._smtp_service_evidence(cast(socket.socket, sock), timeout=1.0)

    assert evidence == {
        "Service Detection": "Port catalog",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Low",
    }
