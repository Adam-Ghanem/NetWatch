import sqlite3

import intelligence_store
import inventory_store


def _use_temporary_database(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")


def _tls_result(**overrides):
    result = {
        "Port": 443,
        "Protocol": "TCP",
        "Service": "HTTPS",
        "Status": "Open",
        "Risk": "Low",
        "Response Time (ms)": 7.5,
        "Service Detection": "TLS handshake",
        "Service Product": "TLS",
        "Service Version": "TLSv1.3",
        "Service Confidence": "High",
        "TLS Protocol": "TLSv1.3",
        "TLS Cipher": "TLS_AES_256_GCM_SHA384",
        "TLS ALPN": "h2",
        "TLS Certificate SHA256": "a" * 64,
        "TLS Certificate Not Before": "2026-08-01T00:00:00+00:00",
        "TLS Certificate Not After": "2026-11-01T00:00:00+00:00",
        "TLS Certificate Status": "Valid",
        "TLS Certificate Days Remaining": "55",
    }
    result.update(overrides)
    return result


def test_tls_service_evidence_is_retained_across_scans(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    target = "2001:db8::20"

    first_run = inventory_store.add_scan_run("ports", target, "first TLS observation")
    inventory_store.update_asset_ports(
        target,
        [_tls_result()],
        exposure_score=1,
        exposure_level="Low",
        scan_run_id=first_run,
    )

    second_run = inventory_store.add_scan_run("ports", target, "second TLS observation")
    inventory_store.update_asset_ports(
        target,
        [
            _tls_result(
                **{
                    "TLS Cipher": "TLS_CHACHA20_POLY1305_SHA256",
                    "TLS ALPN": "http/1.1",
                    "TLS Certificate SHA256": "b" * 64,
                    "TLS Certificate Days Remaining": "54",
                }
            )
        ],
        exposure_score=1,
        exposure_level="Low",
        scan_run_id=second_run,
    )

    history = intelligence_store.recent_tls_service_history(ip_address=target)

    assert len(history) == 2
    assert history[0]["scan_run_id"] == second_run
    assert history[0]["tls_protocol"] == "TLSv1.3"
    assert history[0]["tls_cipher"] == "TLS_CHACHA20_POLY1305_SHA256"
    assert history[0]["tls_alpn"] == "http/1.1"
    assert history[0]["certificate_sha256"] == "b" * 64
    assert history[0]["certificate_status"] == "Valid"
    assert history[0]["certificate_days_remaining"] == "54"
    assert history[1]["scan_run_id"] == first_run
    assert history[1]["certificate_sha256"] == "a" * 64


def test_tls_history_does_not_retain_certificate_body_or_identity(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    target = "192.168.1.40"
    scan_run_id = inventory_store.add_scan_run("ports", target, "TLS privacy test")
    result = _tls_result()
    result["TLS Certificate PEM"] = "-----BEGIN CERTIFICATE-----PRIVATE-DATA"
    result["TLS Certificate Subject"] = "CN=private.internal"
    result["TLS Certificate Issuer"] = "CN=Internal CA"

    inventory_store.update_asset_ports(
        target,
        [result],
        exposure_score=1,
        exposure_level="Low",
        scan_run_id=scan_run_id,
    )

    with sqlite3.connect(inventory_store.DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM tls_service_history").fetchone()

    assert row is not None
    stored = dict(row)
    assert "certificate_pem" not in stored
    assert "certificate_subject" not in stored
    assert "certificate_issuer" not in stored
    assert "PRIVATE-DATA" not in str(stored)
    assert "private.internal" not in str(stored)
    assert "Internal CA" not in str(stored)


def test_tls_history_rejects_malformed_fingerprint_and_unknown_status(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    target = "192.168.1.41"
    scan_run_id = inventory_store.add_scan_run("ports", target, "TLS normalization test")

    inventory_store.update_asset_ports(
        target,
        [
            _tls_result(
                **{
                    "TLS Certificate SHA256": "not-a-sha256",
                    "TLS Certificate Status": "Definitely Fine",
                }
            )
        ],
        exposure_score=1,
        exposure_level="Low",
        scan_run_id=scan_run_id,
    )

    history = intelligence_store.recent_tls_service_history(ip_address=target)

    assert history[0]["certificate_sha256"] == ""
    assert history[0]["certificate_status"] == "Unknown"


def test_non_tls_service_findings_do_not_create_tls_history(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    target = "192.168.1.42"
    scan_run_id = inventory_store.add_scan_run("ports", target, "SSH observation")

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
                "Service Version": "9.8p1",
                "Service Confidence": "High",
            }
        ],
        exposure_score=2,
        exposure_level="Low",
        scan_run_id=scan_run_id,
    )

    assert intelligence_store.recent_tls_service_history(ip_address=target) == []


def test_tls_history_query_validates_address_and_bounds_limit(monkeypatch, tmp_path):
    _use_temporary_database(monkeypatch, tmp_path)
    inventory_store.init_db()

    assert intelligence_store.recent_tls_service_history(limit=0) == []

    try:
        intelligence_store.recent_tls_service_history(ip_address="not-an-ip")
    except ValueError as exc:
        assert "valid IPv4 or IPv6" in str(exc)
    else:
        raise AssertionError("invalid addresses must be rejected")
