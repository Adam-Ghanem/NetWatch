from pathlib import Path

import traffic_capture


def test_capture_interfaces_include_bounded_canonical_ipv6_addresses(monkeypatch):
    monkeypatch.setattr(traffic_capture, "_interface_names", lambda: ["eth0"])
    monkeypatch.setattr(traffic_capture, "_interface_ipv4", lambda _name: "192.168.1.10")
    monkeypatch.setattr(traffic_capture, "_interface_mac", lambda _name: "00:1C:B3:00:00:01")

    original_read_text = Path.read_text

    def fake_read_text(self, *args, **kwargs):
        if str(self) == "/proc/net/if_inet6":
            return "\n".join(
                [
                    "20010db8000000000000000000000010 02 40 00 80 eth0",
                    "fe800000000000000000000000000001 02 40 20 80 eth0",
                    *[
                        f"20010db80000000000000000000000{value:02x} 02 40 00 80 eth0"
                        for value in range(0x20, 0x28)
                    ],
                    "not-an-ipv6-address 02 40 00 80 eth0",
                    "20010db8000000000000000000000099 03 40 00 80 eth1",
                ]
            )
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fake_read_text)

    interfaces = traffic_capture.capture_interfaces()

    assert interfaces == [
        {
            "name": "eth0",
            "ipv4_address": "192.168.1.10",
            "ipv6_addresses": [
                "2001:db8::10",
                "fe80::1",
                "2001:db8::20",
                "2001:db8::21",
                "2001:db8::22",
                "2001:db8::23",
                "2001:db8::24",
                "2001:db8::25",
            ],
            "mac_address": "00:1C:B3:00:00:01",
            "loopback": False,
        }
    ]


def test_interface_ipv6_addresses_fails_closed_when_kernel_table_is_unavailable(monkeypatch):
    def unavailable_read_text(*_args, **_kwargs):
        raise OSError("not available")

    monkeypatch.setattr(Path, "read_text", unavailable_read_text)

    assert traffic_capture._interface_ipv6_addresses("eth0") == []


def test_traffic_interface_selector_surfaces_bounded_ipv6_evidence() -> None:
    core = Path("frontend/app-core.js").read_text(encoding="utf-8")

    assert "const ipv6Addresses = Array.isArray(item.ipv6_addresses)" in core
    assert ".slice(0, 2)" in core
    assert "`IPv6 ${ipv6Addresses.join(', ')}`" in core
    assert "` +${item.ipv6_addresses.length - ipv6Addresses.length}`" in core
    assert "[item.ipv4_address, ipv6Detail, item.mac_address]" in core
    assert "option.value = item.name;" in core
    assert "option.value === previous" in core
