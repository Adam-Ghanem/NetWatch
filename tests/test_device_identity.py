from device_identity import (
    NeighborEntry,
    enrich_host_rows,
    identity_for_ip,
    infer_device_identity,
    is_locally_administered_mac,
    manufacturer_for_mac,
    normalize_mac,
    parse_neighbor_output,
)


def test_mac_normalization_rejects_multicast_and_empty_addresses():
    assert normalize_mac("00-1c-b3-00-00-01") == "00:1C:B3:00:00:01"
    assert normalize_mac("001c.b300.0001") == "00:1C:B3:00:00:01"
    assert normalize_mac("ff:ff:ff:ff:ff:ff") == ""
    assert normalize_mac("01:00:5e:00:00:01") == ""
    assert normalize_mac("not-a-mac") == ""
    assert normalize_mac("00:1c:b3:00:00:01<script>") == ""


def test_private_mac_is_marked_without_inventing_a_vendor():
    identity = infer_device_identity("02:11:22:33:44:55")

    assert is_locally_administered_mac(identity.mac_address)
    assert identity.randomized_mac is True
    assert identity.manufacturer == "Private / randomized"
    assert identity.device_name == "Private-address device"
    assert identity.identity_confidence == "Low"


def test_offline_oui_lookup_and_hostname_evidence_identify_device_families():
    assert "Apple" in manufacturer_for_mac("00:1C:B3:00:00:01")
    assert "XIAOMI" in manufacturer_for_mac("28:6C:07:00:00:01").upper()

    iphone = infer_device_identity("00:1C:B3:00:00:01", "Adam-iPhone")
    redmi = infer_device_identity("28:6C:07:00:00:01", "Redmi-Note")
    xiaomi_vendor_only = infer_device_identity("64:CC:2E:00:00:01")

    assert iphone.device_family == "Apple iPhone"
    assert iphone.device_type == "Mobile device"
    assert iphone.identity_confidence == "High"
    assert redmi.device_family == "Xiaomi Redmi"
    assert redmi.identity_confidence == "High"
    assert xiaomi_vendor_only.device_name == "Xiaomi / Redmi device"
    assert xiaomi_vendor_only.identity_confidence == "Medium"


def test_neighbor_table_parsers_support_linux_unix_and_windows_formats():
    linux = parse_neighbor_output(
        "192.168.1.20 dev wlan0 lladdr 28:6c:07:00:00:01 REACHABLE\n"
        "192.168.1.21 dev wlan0 FAILED\n",
        "ip-neigh",
    )
    unix = parse_neighbor_output(
        "? (192.168.1.30) at 00:1c:b3:00:00:01 [ether] on en0",
        "arp",
    )
    windows = parse_neighbor_output(
        "192.168.1.40          64-cc-2e-00-00-01     dynamic",
        "arp",
    )

    assert linux == [
        NeighborEntry(
            ip_address="192.168.1.20",
            mac_address="28:6C:07:00:00:01",
            interface="wlan0",
            state="REACHABLE",
            source="ip-neigh",
        )
    ]
    assert unix[0].interface == "en0"
    assert unix[0].mac_address == "00:1C:B3:00:00:01"
    assert windows[0].state == "DYNAMIC"


def test_linux_neighbor_parser_keeps_ipv6_neighbor_evidence():
    entries = parse_neighbor_output(
        "fe80::a00:27ff:fe4e:66a1 dev eth0 lladdr 08:00:27:4e:66:a1 STALE\n",
        "ip-neigh",
    )

    assert entries == [
        NeighborEntry(
            ip_address="fe80::a00:27ff:fe4e:66a1",
            mac_address="08:00:27:4E:66:A1",
            interface="eth0",
            state="STALE",
            source="ip-neigh",
        )
    ]


def test_identity_for_ip_uses_ipv6_neighbor_evidence():
    identity = identity_for_ip(
        "2001:db8::20",
        entries=[
            NeighborEntry(
                ip_address="2001:db8::20",
                mac_address="00:1C:B3:00:00:01",
                interface="eth0",
                state="REACHABLE",
                source="ip-neigh",
            )
        ],
    )

    assert identity.mac_address == "00:1C:B3:00:00:01"
    assert identity.manufacturer != "Unknown"
    assert "MAC OUI" in identity.identity_source


def test_scan_rows_are_enriched_from_one_neighbor_snapshot():
    rows = enrich_host_rows(
        [{"IP Address": "192.168.1.20", "Status": "Online", "Details": "reply"}],
        entries=[
            NeighborEntry(
                ip_address="192.168.1.20",
                mac_address="28:6C:07:00:00:01",
                interface="wlan0",
                state="REACHABLE",
                source="ip-neigh",
            )
        ],
    )

    assert rows[0]["MAC Address"] == "28:6C:07:00:00:01"
    assert rows[0]["Device Name"] == "Xiaomi / Redmi device"
    assert rows[0]["Device Type"] == "Personal device"
    assert rows[0]["Identity Confidence"] == "Medium"


def test_scan_rows_can_add_bounded_reverse_dns_hostname(monkeypatch):
    monkeypatch.setattr(
        "device_identity.resolve_hostnames_fn",
        lambda addresses: {"192.168.1.20": "Adam-iPhone"},
    )
    rows = enrich_host_rows(
        [{"IP Address": "192.168.1.20", "Status": "Online", "Details": "reply"}],
        entries=[
            NeighborEntry(
                ip_address="192.168.1.20",
                mac_address="00:1C:B3:00:00:01",
                interface="wlan0",
                state="REACHABLE",
                source="ip-neigh",
            )
        ],
        resolve_hostnames=True,
    )

    assert rows[0]["Hostname"] == "Adam-iPhone"
    assert rows[0]["Device Name"] == "Adam-iPhone"
    assert rows[0]["Identity Confidence"] == "High"
    assert rows[0]["Identity Source"] == "hostname, MAC OUI"


def test_scan_rows_can_disable_hostname_lookup(monkeypatch):
    called = False

    def resolver(_addresses):
        nonlocal called
        called = True
        return {"192.168.1.20": "should-not-be-used"}

    monkeypatch.setattr("device_identity.resolve_hostnames_fn", resolver)
    rows = enrich_host_rows(
        [{"IP Address": "192.168.1.20", "Status": "Online", "Details": "reply"}],
        resolve_hostnames=False,
    )

    assert called is False
    assert rows[0]["Hostname"] == "-"
    assert rows[0]["Device Name"] == "Unknown device"
