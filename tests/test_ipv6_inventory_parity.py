from pathlib import Path

import inventory_store


def _use_temporary_database(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def test_upsert_hosts_persists_canonical_ipv6_identity(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)

    inventory_store.upsert_hosts(
        [
            {
                "IP Address": "2001:0db8:0000:0000:0000:0000:0000:002a",
                "Status": "Online",
                "Device Name": "IPv6 sensor",
                "Identity Confidence": "Medium",
                "Identity Source": "passive neighbor evidence",
            },
            {"IP Address": "fe80::1%eth0", "Status": "Online"},
            {"IP Address": "not-an-ip", "Status": "Online"},
        ]
    )

    inventory = inventory_store.asset_inventory()

    assert [row["ip_address"] for row in inventory] == ["2001:db8::2a"]
    assert inventory[0]["device_name"] == "IPv6 sensor"


def test_ipv6_network_snapshots_track_new_missing_and_returned_assets(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)

    first = inventory_store.record_network_scan(
        "2001:db8::/126",
        [
            {"IP Address": "2001:db8::1", "Status": "Online", "Details": "reply"},
            {"IP Address": "2001:0db8::2", "Status": "Online", "Details": "reply"},
            {"IP Address": "2001:db8:1::1", "Status": "Online"},
            {"IP Address": "192.168.1.10", "Status": "Online"},
        ],
    )
    second = inventory_store.record_network_scan(
        "2001:db8::/126",
        [
            {"IP Address": "2001:db8::2", "Status": "Online", "Details": "reply"},
            {"IP Address": "2001:db8::3", "Status": "Online", "Details": "reply"},
        ],
    )
    third = inventory_store.record_network_scan(
        "2001:db8::/126",
        [
            {"IP Address": "2001:db8::1", "Status": "Online", "Details": "reply"},
            {"IP Address": "2001:db8::2", "Status": "Online", "Details": "reply"},
            {"IP Address": "2001:db8::3", "Status": "Online", "Details": "reply"},
        ],
    )

    assert first.new_assets == ("2001:db8::1", "2001:db8::2")
    assert second.new_assets == ("2001:db8::3",)
    assert second.not_observed_assets == ("2001:db8::1",)
    assert third.returned_assets == ("2001:db8::1",)
    assert {row["ip_address"] for row in inventory_store.asset_inventory()} == {
        "2001:db8::1",
        "2001:db8::2",
        "2001:db8::3",
    }
    assert len(inventory_store.recent_network_observations(100)) == 8


def test_ipv6_port_findings_context_and_timeline_use_same_canonical_asset(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    scan_run_id = inventory_store.add_scan_run(
        "port_audit", "2001:db8::10", "Authorized IPv6 port audit"
    )

    inventory_store.update_asset_ports(
        "2001:0db8:0000:0000:0000:0000:0000:0010",
        [
            {
                "Port": 443,
                "Protocol": "TCP",
                "Service": "https",
                "Status": "Open",
                "Risk": "Low",
                "Response Time (ms)": 4.5,
            }
        ],
        exposure_score=1,
        exposure_level="Low",
        scan_run_id=scan_run_id,
    )
    asset = inventory_store.update_asset_context(
        "2001:db8::10",
        owner="Infrastructure",
        department="IT",
        location="Lab",
        criticality="High",
        notes="IPv6-managed asset",
        actor_role="admin",
    )

    findings = inventory_store.recent_service_findings(
        scan_run_id=scan_run_id,
        ip_address="2001:0db8::10",
    )
    timeline = inventory_store.asset_timeline("2001:0db8::10")

    assert asset["ip_address"] == "2001:db8::10"
    assert asset["owner"] == "Infrastructure"
    assert findings[0]["ip_address"] == "2001:db8::10"
    assert findings[0]["port"] == 443
    assert any(item["target"] == "2001:db8::10" for item in timeline)
