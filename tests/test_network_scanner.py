import network_scanner


def test_worker_count_is_clamped_for_single_host(monkeypatch):
    monkeypatch.setattr(
        network_scanner, "ping_host", lambda _: (True, "Host is online")
    )

    rows = network_scanner.scan_network("127.0.0.1/32", max_workers=0)

    assert rows == [
        {"IP Address": "127.0.0.1", "Status": "Online", "Details": "Host is online"}
    ]
