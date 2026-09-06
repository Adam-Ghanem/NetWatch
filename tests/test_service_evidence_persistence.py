import sqlite3
from pathlib import Path

import inventory_store


def _use_temporary_database(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def test_service_evidence_is_persisted_for_ipv4_and_ipv6(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)

    for target in ("192.168.1.10", "2001:db8::10"):
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
                    "Response Time (ms)": 12.5,
                    "Service Detection": "SSH greeting",
                    "Service Product": "OpenSSH",
                    "Service Version": "9.8p1",
                    "Service Confidence": "High",
                }
            ],
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


def test_existing_service_findings_schema_migrates_without_losing_rows(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                summary TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'completed'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE service_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
                protocol TEXT NOT NULL,
                service TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                risk TEXT NOT NULL DEFAULT 'None',
                response_time_ms REAL,
                observed_at TEXT NOT NULL,
                UNIQUE(scan_run_id, ip_address, protocol, port),
                FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            "INSERT INTO scan_runs (created_at, scan_type, target, summary) VALUES (?, ?, ?, ?)",
            ("2026-09-01T10:00:00+00:00", "ports", "192.168.1.10", "legacy scan"),
        )
        conn.execute(
            """
            INSERT INTO service_findings (
                scan_run_id, ip_address, port, protocol, service,
                status, risk, response_time_ms, observed_at
            ) VALUES (1, '192.168.1.10', 22, 'TCP', 'SSH', 'Open', 'Medium', 8.2, ?)
            """,
            ("2026-09-01T10:00:01+00:00",),
        )
        conn.execute("PRAGMA user_version = 10")

    inventory_store.init_db()

    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(service_findings)")}
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        row = conn.execute(
            """
            SELECT service, service_detection, service_product,
                   service_version, service_confidence
            FROM service_findings
            WHERE id = 1
            """
        ).fetchone()

    assert version == 11
    assert {
        "service_detection",
        "service_product",
        "service_version",
        "service_confidence",
    }.issubset(columns)
    assert row == ("SSH", "", "", "", "")
