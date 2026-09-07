from types import SimpleNamespace

import host_profiler
from device_identity import DeviceIdentity
from host_profiler import os_hint_from_ttl, parse_latency_ms, parse_ttl


def _identity() -> DeviceIdentity:
    return DeviceIdentity(
        hostname="-",
        mac_address="",
        manufacturer="Unknown",
        device_name="Unknown device",
        device_type="Unknown",
        device_family="Unknown",
        identity_confidence="Low",
        identity_source="No identity evidence",
        randomized_mac=False,
    )


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


def test_profile_host_exposes_canonical_ipv6_address_family(monkeypatch):
    monkeypatch.setattr(
        host_profiler,
        "ping_host_raw",
        lambda _target: SimpleNamespace(
            returncode=0,
            stdout="64 bytes from fd00::10: ttl=64 time=1.25 ms",
            stderr="",
        ),
    )
    monkeypatch.setattr(host_profiler, "reverse_hostname", lambda _target: "-")
    monkeypatch.setattr(host_profiler, "identity_for_ip", lambda *_args, **_kwargs: _identity())

    profile = host_profiler.profile_host("fd00::10")

    assert profile.ip_address == "fd00::10"
    assert profile.address_family == "ipv6"


def test_profile_host_exposes_canonical_ipv4_address_family(monkeypatch):
    monkeypatch.setattr(
        host_profiler,
        "ping_host_raw",
        lambda _target: SimpleNamespace(
            returncode=0,
            stdout="64 bytes from 192.168.1.10: ttl=64 time=1.25 ms",
            stderr="",
        ),
    )
    monkeypatch.setattr(host_profiler, "reverse_hostname", lambda _target: "-")
    monkeypatch.setattr(host_profiler, "identity_for_ip", lambda *_args, **_kwargs: _identity())

    profile = host_profiler.profile_host("192.168.1.10")

    assert profile.ip_address == "192.168.1.10"
    assert profile.address_family == "ipv4"
