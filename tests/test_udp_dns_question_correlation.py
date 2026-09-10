import udp_service_scanner


class FakeDatagramSocket:
    def __init__(self, response: bytes):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def settimeout(self, _timeout):
        return None

    def connect(self, _address):
        return None

    def send(self, payload):
        return len(payload)

    def recv(self, size):
        return self.response[:size]


def _factory(sock):
    return lambda *_args, **_kwargs: sock


def test_dns_response_without_echoed_question_does_not_claim_high_confidence(
    monkeypatch,
):
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"NW")
    # Matching transaction ID and QUERY response bit, but the declared question
    # is absent. This must prove only UDP openness, not DNS service identity.
    response = b"\x4e\x57\x80\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    sock = FakeDatagramSocket(response)

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(sock),
    )[0]

    assert row["Status"] == "Open"
    assert row["Service Detection"] == "Unexpected UDP response"
    assert row["Service Product"] == ""
    assert row["Service Confidence"] == "Low"
