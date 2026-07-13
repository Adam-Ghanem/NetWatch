from pathlib import Path

import inventory_store


def _use_temporary_database(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def test_inventory_queries_enforce_requested_limits(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.upsert_hosts(
        [
            {"IP Address": "192.168.1.1"},
            {"IP Address": "192.168.1.2"},
            {"IP Address": "192.168.1.3"},
        ]
    )

    assert len(inventory_store.asset_inventory(limit=2)) == 2
    assert len(inventory_store.asset_inventory(limit=999_999)) == 3


def test_saved_port_data_cannot_override_asset_identity(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.update_asset_ports(
        "192.168.1.10",
        [
            {
                "IP Address": "203.0.113.50",
                "Port": 22,
                "Status": "Open",
                "Risk": "Medium",
            }
        ],
        exposure_score=2,
        exposure_level="Low",
    )

    findings = inventory_store.asset_port_findings()
    inventory = inventory_store.asset_inventory()

    assert findings[0]["IP Address"] == "192.168.1.10"
    assert inventory[0]["status"] == "Seen"
    assert inventory[0]["details"] == "Port audit completed"
