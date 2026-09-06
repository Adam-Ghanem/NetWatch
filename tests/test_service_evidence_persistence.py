import sqlite3

import inventory_store


def _use_temporary_database(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def test_service_evidence_is_persisted_for_ipv4_and_ipv6(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)

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


def test_schema_v10_service_findings_migrate_without_losing_history(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)

    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE service_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER NOT NULL,
                observed_at TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
                protocol TEXT NOT NULL,
                service TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                risk TEXT NOT NULL DEFAULT 'None',
                response_time_ms REAL
            )
            """
        )
        conn.execute(
            """
            INSERT INTO service_findings (
                scan_run_id, observed_at, ip_address, port, protocol,
                service, status, risk, response_time_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                7,
                "2026-09-01T12:00:00+00:00",
                "2001:db8::20",
                443,
                "TCP",
                "HTTPS",
                "Open",
                "Medium",
                8.5,
            ),
        )
        conn.execute("PRAGMA user_version = 10")

    inventory_store.init_db()

    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT scan_run_id, ip_address, port, service,
                   service_detection, service_product, service_version,
                   service_confidence, status, risk, response_time_ms
            FROM service_findings
            """
        ).fetchone()
        version = conn.execute("PRAGMA user_version").fetchone()[0]

    assert version == 11
    assert row is not None
    assert dict(row) == {
        "scan_run_id": 7,
        "ip_address": "2001:db8::20",
        "port": 443,
        "service": "HTTPS",
        "service_detection": "",
        "service_product": "",
        "service_version": "",
        "service_confidence": "",
        "status": "Open",
        "risk": "Medium",
        "response_time_ms": 8.5,
    }
