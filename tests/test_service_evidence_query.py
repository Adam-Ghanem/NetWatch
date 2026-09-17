import csv
import io
import json

import pytest

import service_evidence_query


def _finding(ip_address: str = "192.0.2.10") -> dict[str, object]:
    return {
        "scan_run_id": 17,
        "observed_at": "2026-09-17T03:00:00+00:00",
        "ip_address": ip_address,
        "port": 443,
        "protocol": "TCP",
        "service": "HTTPS",
        "service_detection": "TLS handshake",
        "service_product": "nginx",
        "service_version": "1.26.2",
        "service_confidence": "High",
        "status": "Open",
        "risk": "Medium",
        "response_time_ms": 8.5,
    }


def test_export_recent_service_evidence_reuses_persisted_filters(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def recent_service_findings(**kwargs):
        calls.append(kwargs)
        return [_finding("2001:db8::10")]

    monkeypatch.setattr(
        service_evidence_query.inventory_store,
        "recent_service_findings",
        recent_service_findings,
    )

    payload = json.loads(
        service_evidence_query.export_recent_service_evidence(
            limit=25,
            scan_run_id=17,
            ip_address="2001:db8::10",
        )
    )

    assert calls == [{"limit": 25, "scan_run_id": 17, "ip_address": "2001:db8::10"}]
    assert payload["schema_version"] == "netwatch.service.v1"
    assert payload["count"] == 1
    assert payload["items"][0]["address_family"] == "ipv6"
    assert payload["items"][0]["payload_retained"] is False


def test_export_recent_service_evidence_supports_stable_csv(monkeypatch) -> None:
    monkeypatch.setattr(
        service_evidence_query.inventory_store,
        "recent_service_findings",
        lambda **_: [_finding()],
    )

    exported = service_evidence_query.export_recent_service_evidence(output_format="csv")
    rows = list(csv.DictReader(io.StringIO(exported)))

    assert len(rows) == 1
    assert rows[0]["schema_version"] == "netwatch.service.v1"
    assert rows[0]["ip_address"] == "192.0.2.10"
    assert rows[0]["payload_retained"] == "False"


def test_export_recent_service_evidence_supports_ndjson(monkeypatch) -> None:
    monkeypatch.setattr(
        service_evidence_query.inventory_store,
        "recent_service_findings",
        lambda **_: [_finding(), _finding("2001:db8::10")],
    )

    exported = service_evidence_query.export_recent_service_evidence(output_format="ndjson")
    records = [json.loads(line) for line in exported.splitlines()]

    assert [record["address_family"] for record in records] == ["ipv4", "ipv6"]
    assert all(record["payload_retained"] is False for record in records)


def test_export_recent_service_evidence_rejects_unbounded_or_unknown_output() -> None:
    with pytest.raises(ValueError, match="limit"):
        service_evidence_query.export_recent_service_evidence(limit=0)
    with pytest.raises(ValueError, match="limit"):
        service_evidence_query.export_recent_service_evidence(limit=1001)
    with pytest.raises(ValueError, match="output_format"):
        service_evidence_query.export_recent_service_evidence(output_format="xml")
