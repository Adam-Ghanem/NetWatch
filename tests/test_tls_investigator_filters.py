from __future__ import annotations

import pytest

from tls_change_intelligence import analyze_tls_service_changes


def _row(**overrides):
    row = {
        "scan_run_id": 1,
        "ip_address": "192.0.2.20",
        "port": 443,
        "protocol": "TCP",
        "observed_at": "2026-09-01T10:00:00+00:00",
        "tls_protocol": "TLSv1.3",
        "tls_cipher": "TLS_AES_256_GCM_SHA384",
        "tls_alpn": "h2",
        "certificate_sha256": "a" * 64,
        "certificate_status": "Valid",
        "certificate_days_remaining": "60",
    }
    row.update(overrides)
    return row


def _history():
    return [
        _row(port=443),
        _row(port=8443, certificate_sha256="c" * 64),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            port=443,
            tls_protocol="TLSv1.2",
            certificate_sha256="b" * 64,
        ),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            port=8443,
            certificate_sha256="d" * 64,
        ),
    ]


def test_investigator_filters_can_pivot_to_one_service_and_change_type():
    changes = analyze_tls_service_changes(
        _history(),
        port=443,
        protocol="tcp",
        change_type="tls_protocol_downgrade",
    )

    assert len(changes) == 1
    assert changes[0]["port"] == 443
    assert changes[0]["protocol"] == "TCP"
    assert changes[0]["change_type"] == "tls_protocol_downgrade"


def test_investigator_tracks_negotiated_alpn_changes_as_neutral_evidence():
    history = [
        _row(tls_alpn="h2"),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            tls_alpn="http/1.1",
        ),
    ]

    changes = analyze_tls_service_changes(history, change_type="tls_alpn_changed")

    assert len(changes) == 1
    assert changes[0]["severity"] == "info"
    assert changes[0]["previous"] == "h2"
    assert changes[0]["current"] == "http/1.1"
    assert changes[0]["alert_recommended"] is False


def test_investigator_does_not_invent_alpn_changes_when_evidence_is_missing():
    history = [
        _row(tls_alpn=""),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            tls_alpn="h2",
        ),
    ]

    changes = analyze_tls_service_changes(history, change_type="tls_alpn_changed")

    assert changes == []


def test_investigator_alerts_only_keeps_recommended_evidence():
    changes = analyze_tls_service_changes(_history(), alerts_only=True)

    assert changes
    assert all(change["alert_recommended"] is True for change in changes)
    assert {change["change_type"] for change in changes} == {"tls_protocol_downgrade"}


def test_investigator_severity_filter_is_exact_and_bounded():
    high = analyze_tls_service_changes(_history(), severity="HIGH", limit=1)

    assert len(high) == 1
    assert high[0]["severity"] == "high"


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"port": 0}, "port"),
        ({"protocol": "icmp"}, "protocol"),
        ({"severity": "urgent"}, "severity"),
        ({"change_type": "unknown_change"}, "change type"),
    ],
)
def test_investigator_filters_reject_ambiguous_values(kwargs, message):
    with pytest.raises(ValueError, match=message):
        analyze_tls_service_changes(_history(), **kwargs)
