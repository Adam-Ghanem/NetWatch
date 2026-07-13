import inventory_store


def use_temporary_database(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def test_saved_open_ports_are_available_to_reports(monkeypatch, tmp_path):
    use_temporary_database(monkeypatch, tmp_path)
    inventory_store.update_asset_ports(
        "192.168.1.10",
        [
            {"Port": 22, "Status": "Open", "Risk": "Medium", "Service": "SSH"},
            {"Port": 443, "Status": "Closed", "Risk": "None", "Service": "HTTPS"},
        ],
        exposure_score=2,
        exposure_level="Low",
    )

    findings = inventory_store.asset_open_ports()

    assert findings == [
        {
            "IP Address": "192.168.1.10",
            "Port": 22,
            "Status": "Open",
            "Risk": "Medium",
            "Service": "SSH",
        }
    ]


def test_port_audit_refreshes_stale_asset_status(monkeypatch, tmp_path):
    use_temporary_database(monkeypatch, tmp_path)
    inventory_store.upsert_hosts(
        [{"IP Address": "192.168.1.10", "Status": "Offline", "Details": "old"}]
    )
    inventory_store.update_asset_ports("192.168.1.10", [], 0, "Clean")

    asset = inventory_store.asset_inventory()[0]

    assert asset["status"] == "Seen"
    assert asset["details"] == "Port audit completed"
