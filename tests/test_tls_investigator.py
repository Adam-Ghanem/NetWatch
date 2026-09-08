from __future__ import annotations

import tls_investigator


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
        _row(),
        _row(port=8443, certificate_sha256="c" * 64),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            tls_protocol="TLSv1.2",
            tls_alpn="http/1.1",
            certificate_sha256="b" * 64,
        ),
        _row(
            scan_run_id=2,
            observed_at="2026-09-02T10:00:00+00:00",
            port=8443,
            certificate_sha256="d" * 64,
        ),
    ]


def test_snapshot_facets_match_filtered_evidence():
    snapshot = tls_investigator.build_tls_investigator_snapshot(
        _history(),
        port=443,
        alerts_only=True,
    )

    assert snapshot["history_count"] == 4
    assert snapshot["service_count"] == 2
    assert snapshot["change_count"] == 1
    assert snapshot["alert_recommended_count"] == 1
    assert snapshot["facets"] == {
        "change_types": {"tls_protocol_downgrade": 1},
        "severities": {"high": 1},
    }
    assert snapshot["items"][0]["change_type"] == "tls_protocol_downgrade"


def test_snapshot_keeps_neutral_changes_but_does_not_recommend_alerts():
    snapshot = tls_investigator.build_tls_investigator_snapshot(
        _history(),
        port=443,
        change_type="tls_alpn_changed",
    )

    assert snapshot["change_count"] == 1
    assert snapshot["alert_recommended_count"] == 0
    assert snapshot["items"][0]["previous"] == "h2"
    assert snapshot["items"][0]["current"] == "http/1.1"
    assert snapshot["evidence_scope"]["network_probes_added"] is False
    assert snapshot["evidence_scope"]["certificate_bodies_retained"] is False


def test_recent_snapshot_loads_bounded_history_and_forwards_filters(monkeypatch):
    captured = {}

    def fake_history(*, limit, ip_address):
        captured["history"] = {"limit": limit, "ip_address": ip_address}
        return _history()

    def fake_analyze(history, **kwargs):
        captured["analysis"] = {"history": history, **kwargs}
        return []

    monkeypatch.setattr(tls_investigator, "recent_tls_service_history", fake_history)
    monkeypatch.setattr(tls_investigator, "analyze_tls_service_changes", fake_analyze)

    snapshot = tls_investigator.recent_tls_investigator_snapshot(
        history_limit=9_999,
        limit=25,
        ip_address="2001:db8::20",
        expiry_warning_days=21,
        alert_min_severity="high",
        port=443,
        protocol="tcp",
        change_type="tls_protocol_downgrade",
        severity="high",
        alerts_only=True,
    )

    assert captured["history"] == {
        "limit": 1_000,
        "ip_address": "2001:db8::20",
    }
    assert captured["analysis"]["limit"] == 25
    assert captured["analysis"]["expiry_warning_days"] == 21
    assert captured["analysis"]["alert_min_severity"] == "high"
    assert captured["analysis"]["port"] == 443
    assert captured["analysis"]["protocol"] == "tcp"
    assert captured["analysis"]["change_type"] == "tls_protocol_downgrade"
    assert captured["analysis"]["severity"] == "high"
    assert captured["analysis"]["alerts_only"] is True
    assert snapshot["change_count"] == 0


def test_snapshot_bounds_history_and_change_limits(monkeypatch):
    history = [_row(scan_run_id=index) for index in range(1_100)]
    captured = {}

    def fake_analyze(rows, **kwargs):
        captured["history_count"] = len(rows)
        captured["limit"] = kwargs["limit"]
        return []

    monkeypatch.setattr(tls_investigator, "analyze_tls_service_changes", fake_analyze)

    snapshot = tls_investigator.build_tls_investigator_snapshot(history, limit=50_000)

    assert captured == {"history_count": 1_000, "limit": 1_000}
    assert snapshot["history_count"] == 1_000
