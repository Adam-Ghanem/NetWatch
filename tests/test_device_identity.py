import struct

from device_identity import (
    discover_device_identity,
    infer_device_identity,
    mac_address_type,
    parse_netbios_node_status,
    query_netbios_identity,
    resolve_mac_vendor,
)


def _netbios_record(name: str, suffix: int) -> bytes:
    return name.encode("ascii").ljust(15, b" ") + bytes([suffix]) + struct.pack("!H", 0)


def test_hostname_and_ttl_identify_android_phone_with_confidence():
    identity = infer_device_identity(
        "192.168.1.20",
        ttl=64,
        hostname="Adam-Pixel-8-Pro.local",
    )

    assert identity.device_name == "Adam-Pixel-8-Pro.local"
    assert identity.device_type == "Phone / tablet"
    assert identity.manufacturer == "Google"
    assert identity.device_model == "Pixel 8 Pro"
    assert identity.operating_system == "Android (probable)"
    assert identity.confidence == "High"
    assert "Observed TTL: 64" in identity.evidence


def test_netbios_name_is_strong_windows_evidence():
    identity = infer_device_identity(
        "192.168.1.30",
        ttl=128,
        netbios_name="DESKTOP-ADAM",
        mac_address="00:11:22:33:44:55",
    )

    assert identity.device_name == "DESKTOP-ADAM"
    assert identity.device_type == "Computer"
    assert identity.operating_system == "Windows (probable)"
    assert identity.confidence == "High"
    assert identity.mac_address == "00:11:22:33:44:55"
    assert identity.mac_address_type == "Globally assigned"


def test_redmi_name_exposes_brand_and_model_family_without_guessing():
    identity = infer_device_identity(
        "192.168.1.31",
        ttl=64,
        hostname="Adam-Redmi-Note-13-Pro.local",
    )

    assert identity.manufacturer == "Xiaomi"
    assert identity.device_model == "Redmi Note 13 Pro"
    assert identity.device_type == "Phone / tablet"


def test_private_mac_is_labeled_and_oui_vendor_is_not_guessed(tmp_path):
    vendor_file = tmp_path / "oui.csv"
    vendor_file.write_text(
        "Registry,Assignment,Organization Name\nMA-L,021122,Incorrect Vendor\n",
        encoding="utf-8",
    )

    identity = infer_device_identity(
        "192.168.1.32",
        ttl=64,
        hostname="Adam-iPhone.local",
        mac_address="02:11:22:33:44:55",
        vendor_database_path=str(vendor_file),
    )

    assert identity.manufacturer == "Apple"
    assert identity.mac_address_type == "Private / randomized"
    assert resolve_mac_vendor(identity.mac_address, str(vendor_file)) == ""
    assert "vendor unavailable" in identity.evidence


def test_local_ieee_csv_vendor_lookup_supports_global_mac(tmp_path):
    vendor_file = tmp_path / "oui.csv"
    vendor_file.write_text(
        "Registry,Assignment,Organization Name\nMA-L,001122,Example Devices Ltd\n",
        encoding="utf-8",
    )

    assert mac_address_type("00:11:22:33:44:55") == "Globally assigned"
    assert resolve_mac_vendor("00:11:22:33:44:55", str(vendor_file)) == "Example Devices Ltd"


def test_ttl_only_result_is_explicitly_low_confidence():
    identity = infer_device_identity("192.168.1.40", ttl=64)

    assert identity.device_name == "Unresolved"
    assert identity.operating_system == "Linux/Unix-like or embedded (possible)"
    assert identity.confidence == "Low"


def test_netbios_node_status_parser_extracts_name_and_mac():
    transaction_id = b"\x12\x34"
    record_data = (
        b"\x02"
        + _netbios_record("DESKTOP-ADAM", 0x00)
        + _netbios_record("DESKTOP-ADAM", 0x20)
        + bytes.fromhex("001122334455")
    )
    header = transaction_id + struct.pack("!HHHHH", 0x8500, 0, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 0x0021, 0x0001, 0, len(record_data)) + record_data

    name, mac = parse_netbios_node_status(header + answer, transaction_id)

    assert name == "DESKTOP-ADAM"
    assert mac == "00:11:22:33:44:55"


def test_netbios_query_refuses_public_targets_without_network_access():
    assert query_netbios_identity("8.8.8.8") == ("", "")


def test_discovery_keeps_partial_evidence_when_optional_source_fails(monkeypatch):
    monkeypatch.setattr("device_identity.reverse_hostname", lambda ip: "router.local")
    monkeypatch.setattr(
        "device_identity.query_netbios_identity",
        lambda ip: (_ for _ in ()).throw(OSError("unavailable")),
    )
    monkeypatch.setattr("device_identity.neighbor_mac_address", lambda ip: "")

    identity = discover_device_identity("192.168.1.1", ttl=64)

    assert identity.device_name == "router.local"
    assert identity.device_type == "Router / access point"
