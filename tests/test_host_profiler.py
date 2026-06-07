from host_profiler import os_hint_from_ttl, parse_latency_ms, parse_ttl


def test_parse_latency_from_linux_ping():
    output = "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=2.34 ms"
    assert parse_latency_ms(output) == 2.34


def test_parse_latency_from_windows_ping():
    output = "Reply from 192.168.1.1: bytes=32 time=4ms TTL=128"
    assert parse_latency_ms(output) == 4.0


def test_parse_ttl():
    assert parse_ttl("ttl=64 time=1.2 ms") == 64
    assert parse_ttl("TTL=128") == 128


def test_os_hint_from_ttl():
    assert os_hint_from_ttl(None) == "Unknown"
    assert os_hint_from_ttl(64) == "Linux/Unix or network device"
    assert os_hint_from_ttl(128) == "Windows-like host"
