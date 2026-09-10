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


def test_dns_response_marks_service_open_and_retains_only_metadata(monkeypatch):
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"NW")
    response = b"\x4e\x57\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    sock = FakeDatagramSocket(response=response)

    rows = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        timeout=0.2,
        socket_factory=_factory(sock),
    )

    assert len(rows) == 1
    row = rows[0]
    response_time = row["Response Time (ms)"]
    assert isinstance(response_time, (int, float))
    assert row == {
        "Port": 53,
        "Protocol": "UDP",
        "Service": "DNS",
        "Status": "Open",
        "Response Time (ms)": response_time,
        "Service Detection": "DNS response",
        "Service Product": "DNS",
        "Service Version": "",
        "Service Confidence": "High",
        "DNS RCODE": 0,
        "DNS Authoritative": False,
        "DNS Recursion Available": False,
        "NTP Stratum": "",
        "NTP Leap Indicator": "",
    }
    assert 0 <= response_time <= 1000
    assert len(sock.sent) == 1
    assert len(sock.sent[0]) == 17
    assert sock.sent[0][:2] == b"NW"
    # Header: QUERY, QDCOUNT=1, no answer/authority/additional records.
    assert sock.sent[0][2:12] == b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    # Question: root QNAME, QTYPE=NS (2), QCLASS=IN (1).
    assert sock.sent[0][12:] == b"\x00\x00\x02\x00\x01"
    assert sock.timeout == 0.2


def test_dns_response_extracts_bounded_header_flags_without_payload_retention(monkeypatch):
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"NW")
    # QR=1, AA=1, RA=1, RCODE=3 (NXDOMAIN); remaining bytes are intentionally ignored.
    response = b"\x4e\x57\x84\x83" + (b"\x00" * 8) + b"private-answer-material"
    sock = FakeDatagramSocket(response=response)

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(sock),
    )[0]

    assert row["DNS RCODE"] == 3
    assert row["DNS Authoritative"] is True
    assert row["DNS Recursion Available"] is True
    assert "private-answer-material" not in repr(row)
    assert "NW" not in repr(row)


def test_dns_mismatched_transaction_id_does_not_claim_service_identity(monkeypatch):
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"NW")
    response = b"\x00\x01\x80\x00" + (b"\x00" * 8)
    sock = FakeDatagramSocket(response=response)

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(sock),
    )[0]

    assert row["Status"] == "Open"
    assert row["Service Detection"] == "Unexpected UDP response"
    assert row["Service Product"] == ""
    assert row["Service Confidence"] == "Low"


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


def test_non_standard_dns_opcode_does_not_claim_service_identity(monkeypatch):
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"NW")
    # QR=1, OPCODE=1 (IQUERY), which does not match the QUERY probe we sent.
    response = b"\x4e\x57\x88\x00" + (b"\x00" * 8)
    sock = FakeDatagramSocket(response=response)

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(sock),
    )[0]

    assert row["Status"] == "Open"
    assert row["Service Detection"] == "Unexpected UDP response"
    assert row["Service Product"] == ""
    assert row["Service Confidence"] == "Low"


def test_ntp_broadcast_mode_does_not_claim_client_server_identity(monkeypatch):
    monkeypatch.setattr(
        udp_service_scanner, "_ntp_transmit_timestamp", lambda: b"12345678"
    )
    response = bytearray(48)
    response[0] = 0x25  # LI=0, VN=4, mode=5 broadcast
    response[1] = 2
    response[24:32] = b"12345678"
    sock = FakeDatagramSocket(response=bytes(response))

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("ntp",),
        socket_factory=_factory(sock),
    )[0]

    assert row["Status"] == "Open"
    assert row["Service Detection"] == "Unexpected UDP response"
    assert row["Service Product"] == ""
    assert row["Service Confidence"] == "Low"


def test_ntp_matching_originate_timestamp_claims_identity(monkeypatch):
    monkeypatch.setattr(
        udp_service_scanner, "_ntp_transmit_timestamp", lambda: b"12345678"
    )
    response = bytearray(48)
    response[0] = 0x24  # LI=0, VN=4, mode=4 server
    response[1] = 2
    response[24:32] = b"12345678"
    sock = FakeDatagramSocket(response=bytes(response))

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("ntp",),
        socket_factory=_factory(sock),
    )[0]

    assert row["Status"] == "Open"
    assert row["Service Detection"] == "NTP response"
    assert row["Service Product"] == "NTP"
    assert row["Service Version"] == "4"
    assert row["Service Confidence"] == "High"
    assert row["NTP Stratum"] == 2
    assert row["NTP Leap Indicator"] == 0
    assert "12345678" not in repr(row)


def test_ntp_mismatched_originate_timestamp_does_not_claim_identity(monkeypatch):
    monkeypatch.setattr(
        udp_service_scanner, "_ntp_transmit_timestamp", lambda: b"12345678"
    )
    response = bytearray(48)
    response[0] = 0x24
    response[1] = 2
    response[24:32] = b"87654321"
    sock = FakeDatagramSocket(response=bytes(response))

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("ntp",),
        socket_factory=_factory(sock),
    )[0]

    assert row["Status"] == "Open"
    assert row["Service Detection"] == "Unexpected UDP response"
    assert row["Service Product"] == ""
    assert row["Service Confidence"] == "Low"


def test_invalid_service_name_is_rejected():
    with pytest.raises(ValueError):
        udp_service_scanner.scan_udp_services(
            "192.168.1.10",
            services=("snmp",),
        )


def test_timeout_bounds_are_enforced():
    with pytest.raises(ValueError):
        udp_service_scanner.scan_udp_services(
            "192.168.1.10",
            services=("dns",),
            timeout=0.01,
        )

    with pytest.raises(ValueError):
        udp_service_scanner.scan_udp_services(
            "192.168.1.10",
            services=("dns",),
            timeout=1.01,
        )


def test_public_target_is_rejected_before_socket_creation():
    created = False

    def make_socket(*_args, **_kwargs):
        nonlocal created
        created = True
        return FakeDatagramSocket()

    with pytest.raises(ValueError):
        udp_service_scanner.scan_udp_services(
            "8.8.8.8",
            services=("dns",),
            socket_factory=make_socket,
        )

    assert created is False
