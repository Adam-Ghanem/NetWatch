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
    response = bytes.fromhex("4e57800000010000000000000000020001")
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
    response = bytes.fromhex("4e57848300010000000000000000020001") + b"private-answer-material"
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
    assert rows[0]["Service Detection"] == "ICMP/OS refusal"


def _ntp_correlation(monkeypatch):
    unix_time = 1_700_000_000
    monkeypatch.setattr(udp_service_scanner.time, "time", lambda: unix_time)
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"RND4")
    seconds = unix_time + udp_service_scanner._NTP_UNIX_EPOCH_OFFSET
    return seconds.to_bytes(4, "big") + b"RND4"


def test_ntp_response_extracts_protocol_version_and_header_evidence_only(monkeypatch):
    correlation = _ntp_correlation(monkeypatch)
    # LI=1, VN=4, mode=4 (server), stratum=2; originate timestamp echoes our token.
    response = bytearray(48)
    response[0] = 0x64
    response[1] = 0x02
    response[24:32] = correlation
    sock = FakeDatagramSocket(response=bytes(response))

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
    assert rows[0]["NTP Stratum"] == 2
    assert rows[0]["NTP Leap Indicator"] == 1
    assert rows[0]["DNS RCODE"] == ""
    assert len(sock.sent) == 1
    assert len(sock.sent[0]) == 48
    assert sock.sent[0][40:48] == correlation
    assert correlation not in repr(rows[0]).encode()


def test_ntp_mismatched_originate_timestamp_does_not_claim_service_identity(monkeypatch):
    correlation = _ntp_correlation(monkeypatch)
    response = bytearray(48)
    response[0] = 0x24  # LI=0, VN=4, mode=4
    response[1] = 0x02
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
    assert sock.sent[0][40:48] == correlation


def test_unexpected_udp_response_proves_port_open_without_claiming_service_identity():
    sock = FakeDatagramSocket(response=b"not-a-dns-response")

    rows = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(sock),
    )

    assert rows[0]["Status"] == "Open"
    assert rows[0]["Service Detection"] == "Unexpected UDP response"
    assert rows[0]["Service Product"] == ""
    assert rows[0]["Service Version"] == ""
    assert rows[0]["Service Confidence"] == "Low"
    assert rows[0]["DNS RCODE"] == ""
    assert rows[0]["NTP Stratum"] == ""


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


def test_dns_nonstandard_opcode_does_not_claim_service_identity(monkeypatch):
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"NW")
    # QR=1 with OPCODE=2 (STATUS), but NetWatch sent a standard QUERY (OPCODE=0).
    response = b"\x4e\x57\x90\x00" + (b"\x00" * 8)
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


def test_ntp_broadcast_mode_does_not_claim_client_server_response(monkeypatch):
    correlation = _ntp_correlation(monkeypatch)
    response = bytearray(48)
    response[0] = 0x25  # LI=0, VN=4, mode=5 broadcast
    response[1] = 0x02
    response[24:32] = correlation
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
