import udp_service_scanner


class _Socket:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def settimeout(self, _timeout):
        pass

    def connect(self, _address):
        pass

    def send(self, payload):
        return len(payload)

    def recv(self, size):
        return self.response[:size]


def _factory(sock):
    return lambda *_args, **_kwargs: sock


def test_udp_response_size_is_retained_without_payload_content(monkeypatch):
    monkeypatch.setattr(udp_service_scanner.secrets, "token_bytes", lambda size: b"NW")
    response = bytes.fromhex("4e57800000010000000000000000020001") + b"private-answer-material"

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(_Socket(response)),
    )[0]

    assert row["UDP Response Bytes"] == len(response)
    assert "private-answer-material" not in repr(row)


def test_silent_udp_probe_reports_zero_response_bytes():
    class _TimeoutSocket(_Socket):
        def recv(self, size):
            raise TimeoutError

    row = udp_service_scanner.scan_udp_services(
        "192.168.1.10",
        services=("dns",),
        socket_factory=_factory(_TimeoutSocket(b"")),
    )[0]

    assert row["UDP Response Bytes"] == 0
