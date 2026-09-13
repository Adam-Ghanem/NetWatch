from __future__ import annotations

import json

import netwatch_udp


def _normalized_rows() -> list[dict[str, object]]:
    return [
        {
            "Status": "Open",
            "Evidence Verdict": "service_identity_verified",
            "Evidence Semantics": "response_observed",
            "Port State Verified": True,
            "Service Identity Verified": True,
            "UDP Response Bytes": 84,
        },
        {
            "Status": "Open",
            "Evidence Verdict": "port_open_service_unverified",
            "Evidence Semantics": "response_observed",
            "Port State Verified": True,
            "Service Identity Verified": False,
            "UDP Response Bytes": 17,
        },
        {
            "Status": "Open|Filtered",
            "Evidence Verdict": "no_response",
            "Evidence Semantics": "no_response",
            "Port State Verified": False,
            "Service Identity Verified": False,
            "UDP Response Bytes": 0,
        },
        {
            "Status": "Closed",
            "Evidence Verdict": "port_closed",
            "Evidence Semantics": "explicit_refusal",
            "Port State Verified": True,
            "Service Identity Verified": False,
            "UDP Response Bytes": 0,
        },
    ]


def test_run_summary_aggregates_evidence_without_payload_material() -> None:
    summary = netwatch_udp._run_summary(_normalized_rows())

    assert summary == {
        "records": 4,
        "verified_port_states": 3,
        "verified_service_identities": 1,
        "responses_observed": 2,
        "udp_response_bytes_total": 101,
        "status_counts": {
            "Open": 2,
            "Open|Filtered": 1,
            "Closed": 1,
        },
        "verdict_counts": {
            "service_identity_verified": 1,
            "port_open_service_unverified": 1,
            "no_response": 1,
            "port_closed": 1,
        },
    }
    assert "payload" not in json.dumps(summary).lower()


def test_run_summary_tolerates_missing_or_non_numeric_response_size() -> None:
    rows = [
        {
            "Status": "Blocked",
            "Evidence Verdict": "validation_blocked",
            "Evidence Semantics": "validation_blocked",
            "Port State Verified": False,
            "Service Identity Verified": False,
        },
        {
            "Status": "Open",
            "Evidence Verdict": "port_open_evidence_unclassified",
            "Evidence Semantics": "response_observed",
            "Port State Verified": True,
            "Service Identity Verified": False,
            "UDP Response Bytes": "unexpected",
        },
    ]

    summary = netwatch_udp._run_summary(rows)

    assert summary["records"] == 2
    assert summary["udp_response_bytes_total"] == 0
    assert summary["status_counts"] == {"Blocked": 1, "Open": 1}
    assert summary["verdict_counts"] == {
        "validation_blocked": 1,
        "port_open_evidence_unclassified": 1,
    }
