import inventory_store


def test_service_evidence_is_persisted_for_ipv4_and_ipv6(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")

    service_result = {
        "Port": 22,
        "Protocol": "TCP",
        "Service": "SSH",
        "Status": "Open",
        "Risk": "Medium",
        "Response Time (ms)": 12.5,
        "Service Detection": "SSH greeting",
        "Service Product": "OpenSSH",
        "Service Version": "9.8p1",
        "Service Confidence": "High",
    }

    for target in ("192.168.1.10", "2001:db8::10"):
        scan_run_id = inventory_store.add_scan_run(
            "ports",
            target,
            "port audit completed",
        )
        inventory_store.update_asset_ports(
            target,
            [service_result],
            exposure_score=2,
            exposure_level="Low",
            scan_run_id=scan_run_id,
        )
        finding = inventory_store.recent_service_findings(
            scan_run_id=scan_run_id,
            ip_address=target,
        )[0]

        assert finding["service_detection"] == "SSH greeting"
        assert finding["service_product"] == "OpenSSH"
        assert finding["service_version"] == "9.8p1"
        assert finding["service_confidence"] == "High"
