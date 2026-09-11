import udp_service_scanner


class FakeDatagramSocket:
    def __init__(self, response: bytes):
        self.response = response
        self.sent: list[bytes] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def settimeout(self, _timeout):
        pass

    def connect(self, _address):
        pass

    def send(self, payload):
        self.sent.append(payload)
        return len(payload)

    def recv(self, size):
        return self.response[:size]


def test_dns_truncation_flag_is_exposed_as_bounded_header_evidence(monkeypatch):
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"NW")
    # QR=1, TC=1, QDCOUNT=1, and the exact root NS/IN question echoed.
    response = bytes.fromhex("4e57820000010000000000000000020001")
    sock = FakeDatagramSocket(response)

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=lambda *_args, **_kwargs: sock,
    )[0]

    assert row["Status"] == "Open"
    assert row["Service Confidence"] == "High"
    assert row["DNS Truncated"] is True


def test_non_dns_rows_keep_dns_truncation_evidence_empty(monkeypatch):
    unix_time = 1_700_000_000
    monkeypatch.setattr(udp_service_scanner.time, "time", lambda: unix_time)
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"RND4")
    seconds = unix_time + udp_service_scanner._NTP_UNIX_EPOCH_OFFSET
    correlation = seconds.to_bytes(4, "big") + b"RND4"
    response = bytearray(48)
    response[0] = 0x24
    response[1] = 2
    response[24:32] = correlation
    sock = FakeDatagramSocket(bytes(response))

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("ntp",),
        socket_factory=lambda *_args, **_kwargs: sock,
    )[0]

    assert row["DNS Truncated"] == ""
