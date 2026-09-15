import json
from pathlib import Path

import pytest

from service_evidence import (
    MAX_SERVICE_EVIDENCE_RECORDS,
    SERVICE_EVIDENCE_SCHEMA_VERSION,
    SERVICE_EVIDENCE_SOURCE,
    normalize_service_evidence,
    normalize_service_evidence_rows,
)

SCHEMA = Path("schemas/netwatch-service-v1.schema.json")


def _finding(ip_address: str = "192.0.2.10") -> dict[str, object]:
    return {
        "scan_run_id": 17,
        "observed_at": "2026-09-14T17:00:00+00:00",
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


def test_normalize_service_evidence_adds_schema_privacy_and_address_family() -> None:
    ipv4 = normalize_service_evidence(_finding())
    ipv6 = normalize_service_evidence(_finding("2001:db8::10"))

    assert ipv4["schema_version"] == SERVICE_EVIDENCE_SCHEMA_VERSION
    assert ipv4["evidence_source"] == SERVICE_EVIDENCE_SOURCE
    assert ipv4["payload_retained"] is False
    assert ipv4["address_family"] == "ipv4"
    assert ipv6["address_family"] == "ipv6"
    assert ipv4["service_confidence"] == "High"
    assert ipv4["observed_at"] == "2026-09-14T17:00:00+00:00"


def test_normalize_service_evidence_rejects_invalid_identity_fields() -> None:
    bad_ip = _finding("not-an-ip")
    with pytest.raises(ValueError, match="valid IP"):
        normalize_service_evidence(bad_ip)

    bad_port = _finding()
    bad_port["port"] = 70000
    with pytest.raises(ValueError, match="port"):
        normalize_service_evidence(bad_port)


def test_normalize_service_evidence_rejects_boolean_numeric_fields() -> None:
    bad_response_time = _finding()
    bad_response_time["response_time_ms"] = True

    with pytest.raises(ValueError, match="response_time_ms"):
        normalize_service_evidence(bad_response_time)


def test_service_evidence_batch_is_bounded_and_preserves_order() -> None:
    rows = [_finding("192.0.2.10"), _finding("2001:db8::10"), _finding("192.0.2.11")]

    normalized = normalize_service_evidence_rows(rows, limit=2)

    assert [row["ip_address"] for row in normalized] == ["192.0.2.10", "2001:db8::10"]
    assert all(row["schema_version"] == SERVICE_EVIDENCE_SCHEMA_VERSION for row in normalized)
    assert all(row["payload_retained"] is False for row in normalized)


def test_service_evidence_batch_rejects_unbounded_limits() -> None:
    with pytest.raises(ValueError, match="limit"):
        normalize_service_evidence_rows([], limit=0)
    with pytest.raises(ValueError, match="limit"):
        normalize_service_evidence_rows([], limit=MAX_SERVICE_EVIDENCE_RECORDS + 1)


def test_machine_readable_schema_covers_normalized_service_evidence() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    record = normalize_service_evidence(_finding())

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"]["const"] == SERVICE_EVIDENCE_SCHEMA_VERSION
    assert schema["properties"]["evidence_source"]["const"] == SERVICE_EVIDENCE_SOURCE
    assert schema["properties"]["payload_retained"]["const"] is False
    assert set(schema["required"]).issubset(record)
    assert schema["additionalProperties"] is False
    assert "payload" not in schema["properties"]
    assert "raw" not in schema["properties"]
