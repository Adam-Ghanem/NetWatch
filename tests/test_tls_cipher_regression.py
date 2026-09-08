from tls_change_intelligence import analyze_tls_service_changes
from tls_cipher_posture import is_confirmed_cipher_regression, tls_cipher_posture


def _observation(*, run_id: int, cipher: str, observed_at: str) -> dict[str, object]:
    return {
        "scan_run_id": run_id,
        "ip_address": "192.168.1.10",
        "port": 443,
        "protocol": "TCP",
        "observed_at": observed_at,
        "tls_protocol": "TLSv1.2",
        "tls_cipher": cipher,
        "tls_alpn": "h2",
        "certificate_sha256": "a" * 64,
        "certificate_status": "Valid",
        "certificate_days_remaining": 90,
    }


def test_cipher_posture_is_deliberately_conservative() -> None:
    assert tls_cipher_posture("TLS_AES_256_GCM_SHA384") == "modern_aead"
    assert tls_cipher_posture("ECDHE-RSA-CHACHA20-POLY1305") == "modern_aead"
    assert tls_cipher_posture("TLS_RSA_WITH_3DES_EDE_CBC_SHA") == "legacy_unsafe"
    assert tls_cipher_posture("TLS_RSA_WITH_RC4_128_SHA") == "legacy_unsafe"
    assert tls_cipher_posture("TLS_RSA_WITH_AES_256_CBC_SHA") == "unknown"
    assert tls_cipher_posture(object()) == "unknown"


def test_known_modern_to_known_legacy_cipher_is_high_risk_regression() -> None:
    history = [
        _observation(
            run_id=1,
            cipher="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            observed_at="2026-09-08T01:00:00+00:00",
        ),
        _observation(
            run_id=2,
            cipher="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            observed_at="2026-09-08T02:00:00+00:00",
        ),
    ]

    changes = analyze_tls_service_changes(
        history, change_type="tls_cipher_regression"
    )

    assert len(changes) == 1
    change = changes[0]
    assert change["severity"] == "high"
    assert change["alert_recommended"] is True
    assert change["previous"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert change["current"] == "TLS_RSA_WITH_3DES_EDE_CBC_SHA"


def test_unknown_cipher_change_stays_neutral_evidence() -> None:
    history = [
        _observation(
            run_id=1,
            cipher="TLS_RSA_WITH_AES_256_CBC_SHA",
            observed_at="2026-09-08T01:00:00+00:00",
        ),
        _observation(
            run_id=2,
            cipher="VENDOR_CUSTOM_SUITE",
            observed_at="2026-09-08T02:00:00+00:00",
        ),
    ]

    changes = analyze_tls_service_changes(history, change_type="tls_cipher_changed")

    assert len(changes) == 1
    assert changes[0]["severity"] == "info"
    assert changes[0]["alert_recommended"] is False
    assert (
        is_confirmed_cipher_regression(
            "TLS_RSA_WITH_AES_256_CBC_SHA", "VENDOR_CUSTOM_SUITE"
        )
        is False
    )


def test_legacy_to_modern_change_is_not_mislabeled_as_regression() -> None:
    history = [
        _observation(
            run_id=1,
            cipher="TLS_RSA_WITH_RC4_128_SHA",
            observed_at="2026-09-08T01:00:00+00:00",
        ),
        _observation(
            run_id=2,
            cipher="TLS_AES_128_GCM_SHA256",
            observed_at="2026-09-08T02:00:00+00:00",
        ),
    ]

    changes = analyze_tls_service_changes(history, change_type="tls_cipher_changed")

    assert len(changes) == 1
    assert changes[0]["severity"] == "info"
    assert changes[0]["alert_recommended"] is False
