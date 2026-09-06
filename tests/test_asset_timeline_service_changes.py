import inventory_store


def _use_temporary_database(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def _record_ssh_version(target: str, version: str) -> None:
    scan_run_id = inventory_store.add_scan_run("ports", target, "port audit completed")
    inventory_store.update_asset_ports(
        target,
        [
            {
                "Port": 22,
                "Protocol": "TCP",
                "Service": "SSH",
                "Status": "Open",
                "Risk": "Medium",
                "Service Detection": "SSH greeting",
                "Service Product": "OpenSSH",
                "Service Version": version,
                "Service Confidence": "High",
            }
        ],
        exposure_score=2,
        exposure_level="Low",
        scan_run_id=scan_run_id,
    )


def test_asset_timeline_includes_service_version_change_evidence(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    target = "2001:db8::42"
    _record_ssh_version(target, "9.7p1")
    _record_ssh_version(target, "9.8p1")

    timeline = inventory_store.asset_timeline(target)
    changes = [item for item in timeline if item.get("kind") == "service_version_change"]

    assert len(changes) == 1
    assert changes[0]["event_label"] == "Service version changed"
    assert changes[0]["target"] == "[2001:db8::42]:22/tcp"
    assert changes[0]["old_product"] == "OpenSSH"
    assert changes[0]["old_version"] == "9.7p1"
    assert changes[0]["new_product"] == "OpenSSH"
    assert changes[0]["new_version"] == "9.8p1"
    assert changes[0]["service_detection"] == "SSH greeting"
    assert changes[0]["service_confidence"] == "High"
    assert changes[0]["details"] == (
        "OpenSSH 9.7p1 → OpenSSH 9.8p1 · SSH greeting · High confidence"
    )


def test_asset_timeline_suppresses_unchanged_service_versions(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    target = "192.168.1.42"
    _record_ssh_version(target, "9.8p1")
    _record_ssh_version(target, "9.8p1")

    timeline = inventory_store.asset_timeline(target)

    assert not any(item.get("kind") == "service_version_change" for item in timeline)
