from __future__ import annotations

import service_change_intelligence


def _finding(
    *,
    scan_run_id: int,
    observed_at: str,
    status: str,
    service: str = "https",
    port: int = 443,
    protocol: str = "TCP",
    detection: str = "TLS handshake",
    risk: str = "Medium",
) -> dict:
    return {
        "scan_run_id": scan_run_id,
        "observed_at": observed_at,
        "ip_address": "192.168.1.25",
        "port": port,
        "protocol": protocol,
        "service": service,
        "service_detection": detection,
        "service_product": "TLS",
        "service_version": "TLSv1.3",
        "service_confidence": "High",
        "status": status,
        "risk": risk,
    }


def test_build_service_state_changes_detects_service_becoming_open() -> None:
    changes = service_change_intelligence.build_service_state_changes(
        [
            _finding(scan_run_id=1, observed_at="2026-09-07T07:00:00+00:00", status="Closed"),
            _finding(scan_run_id=2, observed_at="2026-09-07T08:00:00+00:00", status="Open"),
        ]
    )

    assert len(changes) == 1
    change = changes[0]
    assert change["event_type"] == "service_became_open"
    assert change["event_label"] == "Service became reachable"
    assert change["old_status"] == "Closed"
    assert change["new_status"] == "Open"
    assert change["target"] == "192.168.1.25:443/tcp"
    assert change["alert_recommended"] is False
    assert "Reachability changed from Closed to Open" in change["details"]


def test_newly_reachable_remote_admin_service_recommends_high_alert() -> None:
    changes = service_change_intelligence.build_service_state_changes(
        [
            _finding(
                scan_run_id=1,
                observed_at="2026-09-07T07:00:00+00:00",
                status="Closed",
                service="ssh",
                port=22,
                detection="Port catalog",
            ),
            _finding(
                scan_run_id=2,
                observed_at="2026-09-07T08:00:00+00:00",
                status="Open",
                service="ssh",
                port=22,
                detection="SSH greeting",
            ),
        ]
    )

    change = changes[0]
    assert change["alert_recommended"] is True
    assert change["alert_severity"] == "high"
    assert change["alert_reason"] == "Remote administration service became reachable"


def test_repeated_reachability_alert_is_suppressed_inside_dedup_window() -> None:
    changes = service_change_intelligence.build_service_state_changes(
        [
            _finding(
                scan_run_id=1,
                observed_at="2026-09-07T08:00:00+00:00",
                status="Closed",
                service="ssh",
                port=22,
            ),
            _finding(
                scan_run_id=2,
                observed_at="2026-09-07T08:01:00+00:00",
                status="Open",
                service="ssh",
                port=22,
            ),
            _finding(
                scan_run_id=3,
                observed_at="2026-09-07T08:02:00+00:00",
                status="Filtered/Timeout",
                service="ssh",
                port=22,
            ),
            _finding(
                scan_run_id=4,
                observed_at="2026-09-07T08:03:00+00:00",
                status="Open",
                service="ssh",
                port=22,
            ),
        ],
        alert_dedupe_seconds=900,
    )

    became_open = [change for change in changes if change["event_type"] == "service_became_open"]
    assert len(became_open) == 2
    assert became_open[0]["alert_recommended"] is False
    assert became_open[0]["alert_suppressed"] is True
    assert became_open[0]["alert_suppression_reason"] == "Duplicate reachability alert suppressed"
    assert became_open[1]["alert_recommended"] is True
    assert became_open[1]["alert_suppressed"] is False


def test_alert_threshold_can_suppress_high_reachability_alert() -> None:
    changes = service_change_intelligence.build_service_state_changes(
        [
            _finding(
                scan_run_id=1,
                observed_at="2026-09-07T07:00:00+00:00",
                status="Closed",
                service="ssh",
                port=22,
            ),
            _finding(
                scan_run_id=2,
                observed_at="2026-09-07T08:00:00+00:00",
                status="Open",
                service="ssh",
                port=22,
            ),
        ],
        minimum_alert_severity="critical",
    )

    assert changes[0]["alert_recommended"] is False
    assert changes[0]["alert_reason"] == ""


def test_build_service_state_changes_does_not_overstate_filtered_result() -> None:
    changes = service_change_intelligence.build_service_state_changes(
        [
            _finding(scan_run_id=1, observed_at="2026-09-07T07:00:00+00:00", status="Open"),
            _finding(
                scan_run_id=2,
                observed_at="2026-09-07T08:00:00+00:00",
                status="Filtered/Timeout",
            ),
        ]
    )

    assert len(changes) == 1
    change = changes[0]
    assert change["event_type"] == "service_open_not_confirmed"
    assert change["event_label"] == "Service no longer confirmed open"
    assert change["old_status"] == "Open"
    assert change["new_status"] == "Filtered/Timeout"
    assert change["alert_recommended"] is False
    assert "does not by itself prove the service is down" in change["details"]


def test_build_service_state_changes_treats_open_filtered_as_not_confirmed_open() -> None:
    changes = service_change_intelligence.build_service_state_changes(
        [
            _finding(
                scan_run_id=1,
                observed_at="2026-09-07T07:00:00+00:00",
                status="Open|Filtered",
                service="dns",
                port=53,
                protocol="UDP",
                detection="DNS probe",
            ),
            _finding(
                scan_run_id=2,
                observed_at="2026-09-07T08:00:00+00:00",
                status="Open",
                service="dns",
                port=53,
                protocol="UDP",
                detection="DNS response",
            ),
        ]
    )

    assert len(changes) == 1
    assert changes[0]["event_type"] == "service_became_open"
    assert changes[0]["target"] == "192.168.1.25:53/udp"
    assert changes[0]["old_status"] == "Open|Filtered"
    assert changes[0]["new_status"] == "Open"
    assert changes[0]["alert_recommended"] is False


def test_build_service_state_changes_ignores_non_open_to_non_open_transitions() -> None:
    changes = service_change_intelligence.build_service_state_changes(
        [
            _finding(scan_run_id=1, observed_at="2026-09-07T07:00:00+00:00", status="Closed"),
            _finding(
                scan_run_id=2,
                observed_at="2026-09-07T08:00:00+00:00",
                status="Filtered/Timeout",
            ),
        ]
    )

    assert changes == []


def test_build_service_state_changes_handles_ipv6_targets_and_limit() -> None:
    rows = [
        {
            **_finding(
                scan_run_id=1,
                observed_at="2026-09-07T07:00:00+00:00",
                status="Closed",
            ),
            "ip_address": "2001:db8::25",
        },
        {
            **_finding(
                scan_run_id=2,
                observed_at="2026-09-07T08:00:00+00:00",
                status="Open",
            ),
            "ip_address": "2001:db8::25",
        },
        {
            **_finding(
                scan_run_id=3,
                observed_at="2026-09-07T09:00:00+00:00",
                status="Closed",
            ),
            "ip_address": "2001:db8::25",
        },
    ]

    changes = service_change_intelligence.build_service_state_changes(rows, limit=1)

    assert len(changes) == 1
    assert changes[0]["target"] == "[2001:db8::25]:443/tcp"
    assert changes[0]["event_type"] == "service_open_not_confirmed"


def test_asset_service_version_changes_keeps_version_and_state_events(monkeypatch) -> None:
    rows = [
        {
            **_finding(scan_run_id=1, observed_at="2026-09-07T07:00:00+00:00", status="Closed"),
            "service_product": "",
            "service_version": "",
            "service_confidence": "Low",
            "service_detection": "Port catalog",
        },
        _finding(scan_run_id=2, observed_at="2026-09-07T08:00:00+00:00", status="Open"),
        {
            **_finding(scan_run_id=3, observed_at="2026-09-07T09:00:00+00:00", status="Open"),
            "service_version": "TLSv1.2",
        },
    ]
    monkeypatch.setattr(
        service_change_intelligence.inventory_store,
        "recent_service_findings",
        lambda **_: rows,
    )

    changes = service_change_intelligence.asset_service_version_changes("192.168.1.25")

    assert [change["event_type"] for change in changes] == [
        "service_version_change",
        "service_became_open",
    ]
