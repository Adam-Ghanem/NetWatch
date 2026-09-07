from __future__ import annotations

from tls_change_intelligence import analyze_tls_service_changes


def _row(**overrides):
    row = {
        "scan_run_id": 1,
        "ip_address": "192.168.1.20",
        "port": 443,
        "protocol": "TCP",
        "observed_at": "2026-09-01T10:00:00+00:00",
        "tls_protocol": "TLSv1.3",
        "tls_cipher": "TLS_AES_256_GCM_SHA384",
        "tls_alpn": "h2",
        "certificate_sha256": "a" * 64,
        "certificate_not_before": "2026-08-01T00:00:00+00:00",
        "certificate_not_after": "2026-11-01T00:00:00+00:00",
        "certificate_status": "Valid",
        "certificate_days_remaining": "61",
    }
    row.update(overrides)
    return row


def test_detects_certificate_rotation_protocol_downgrade_and_cipher_change():
    history = [
        _row(),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            tls_protocol="TLSv1.2",
            tls_cipher="ECDHE-RSA-AES256-GCM-SHA384",
            certificate_sha256="b" * 64,
            certificate_days_remaining="60",
        ),
    ]

    changes = analyze_tls_service_changes(history)

    by_type = {change["change_type"]: change for change in changes}
    assert by_type["certificate_rotated"]["severity"] == "info"
    assert by_type["tls_protocol_downgrade"]["severity"] == "high"
    assert by_type["tls_protocol_downgrade"]["previous"] == "TLSv1.3"
    assert by_type["tls_protocol_downgrade"]["current"] == "TLSv1.2"
    assert by_type["tls_cipher_changed"]["severity"] == "info"


def test_protocol_change_is_not_called_downgrade_when_versions_are_unknown():
    history = [
        _row(tls_protocol="vendor-tls-a"),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            tls_protocol="vendor-tls-b",
        ),
    ]

    changes = analyze_tls_service_changes(history)

    assert [change["change_type"] for change in changes] == ["tls_protocol_changed"]
    assert changes[0]["severity"] == "info"


def test_detects_entry_into_expiry_warning_window_once():
    history = [
        _row(certificate_days_remaining="31"),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            certificate_days_remaining="30",
        ),
        _row(
            scan_run_id=3,
            observed_at="2026-09-03T10:00:00+00:00",
            certificate_days_remaining="29",
        ),
    ]

    changes = analyze_tls_service_changes(history, expiry_warning_days=30)

    expiry = [change for change in changes if change["change_type"] == "certificate_expiry_risk"]
    assert len(expiry) == 1
    assert expiry[0]["scan_run_id"] == 2
    assert expiry[0]["severity"] == "medium"


def test_detects_expired_and_not_yet_valid_status_transitions():
    expired = analyze_tls_service_changes(
        [
            _row(),
            _row(
                scan_run_id=2,
                observed_at="2026-09-02T10:00:00+00:00",
                certificate_status="Expired",
                certificate_days_remaining="-1",
            ),
        ]
    )
    future = analyze_tls_service_changes(
        [
            _row(),
            _row(
                scan_run_id=2,
                observed_at="2026-09-02T10:00:00+00:00",
                certificate_status="Not Yet Valid",
                certificate_days_remaining="90",
            ),
        ]
    )

    assert any(
        change["change_type"] == "certificate_validity_risk"
        and change["current"] == "Expired"
        and change["severity"] == "high"
        for change in expired
    )
    assert any(
        change["change_type"] == "certificate_validity_risk"
        and change["current"] == "Not Yet Valid"
        for change in future
    )


def test_keeps_services_independent_and_requires_consecutive_evidence():
    history = [
        _row(port=443, certificate_sha256="a" * 64),
        _row(port=8443, certificate_sha256="x" * 64),
        _row(
            scan_run_id=2,
            port=443,
            observed_at="2026-09-02T10:00:00+00:00",
            certificate_sha256="b" * 64,
        ),
    ]

    changes = analyze_tls_service_changes(history)

    rotations = [change for change in changes if change["change_type"] == "certificate_rotated"]
    assert len(rotations) == 1
    assert rotations[0]["port"] == 443


def test_malformed_or_missing_evidence_does_not_create_speculative_changes():
    history = [
        _row(certificate_sha256="", tls_protocol="", tls_cipher=""),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            certificate_sha256="not-a-fingerprint",
            tls_protocol="TLSv1.3",
            tls_cipher="TLS_AES_256_GCM_SHA384",
            certificate_status="Unknown",
            certificate_days_remaining="not-a-number",
        ),
    ]

    assert analyze_tls_service_changes(history) == []


def test_results_are_newest_first_and_limit_is_bounded():
    history = [
        _row(),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            certificate_sha256="b" * 64,
        ),
        _row(
            scan_run_id=3,
            observed_at="2026-09-03T10:00:00+00:00",
            certificate_sha256="c" * 64,
        ),
    ]

    changes = analyze_tls_service_changes(history, limit=1)

    assert len(changes) == 1
    assert changes[0]["scan_run_id"] == 3
