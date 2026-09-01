from __future__ import annotations

import pytest

from protocol_expert import ProtocolExpertPolicy, analyze_protocol_expert_findings


def _flow(flow_id: str, events: list[dict[str, object]]) -> dict[str, object]:
    return {
        "flow_id": flow_id,
        "originator": {"ip": "10.0.0.10", "port": 51515},
        "responder": {"ip": "10.0.0.1", "port": 443},
        "protocol": "tcp",
        "protocol_events": events,
        "payload": "must-not-leak",
    }


def test_flags_deprecated_tls_without_copying_sensitive_metadata() -> None:
    flows = [
        _flow(
            "flow-tls",
            [
                {
                    "event_type": "tls",
                    "timestamp": "2026-09-01T12:00:00Z",
                    "metadata": {
                        "version": "TLSv1.0",
                        "server_name": "legacy.example",
                        "authorization": "secret",
                    },
                }
            ],
        )
    ]

    findings = analyze_protocol_expert_findings(flows)

    assert findings == [
        {
            "signal": "deprecated_tls_version",
            "severity": "high",
            "entity": "flow-tls",
            "flow_ids": ["flow-tls"],
            "observed": "TLSv1.0",
            "threshold": "TLS 1.2+",
            "explanation": (
                "The flow negotiated a deprecated TLS version; validate legacy dependencies "
                "and migrate the service to TLS 1.2 or newer."
            ),
        }
    ]
    assert "secret" not in repr(findings)
    assert "must-not-leak" not in repr(findings)


def test_flags_dns_and_http_failure_bursts_per_flow() -> None:
    events: list[dict[str, object]] = []
    events.extend(
        {
            "event_type": "dns",
            "metadata": {"rcode": "NXDOMAIN", "query": f"missing-{index}.example"},
        }
        for index in range(3)
    )
    events.extend(
        {
            "event_type": "http",
            "metadata": {"status_code": 503, "host": "service.example"},
        }
        for _ in range(4)
    )
    flows = [_flow("flow-errors", events)]

    findings = analyze_protocol_expert_findings(flows)

    assert [finding["signal"] for finding in findings] == [
        "dns_error_burst",
        "http_server_error_burst",
    ]
    assert findings[0]["observed"] == 3
    assert findings[0]["threshold"] == 3
    assert findings[1]["observed"] == 4
    assert findings[1]["threshold"] == 3
    assert "missing-" not in repr(findings)
    assert "service.example" not in repr(findings)


def test_policy_bounds_fail_closed_and_limit_findings() -> None:
    with pytest.raises(ValueError, match="between 1 and 50000"):
        ProtocolExpertPolicy(max_flows=0).validate()

    flows = [
        _flow(
            f"flow-{index}",
            [{"event_type": "tls", "metadata": {"version": "TLS 1.1"}}],
        )
        for index in range(3)
    ]

    findings = analyze_protocol_expert_findings(
        flows,
        policy=ProtocolExpertPolicy(max_findings=2),
    )

    assert len(findings) == 2
    assert [finding["entity"] for finding in findings] == ["flow-0", "flow-1"]
