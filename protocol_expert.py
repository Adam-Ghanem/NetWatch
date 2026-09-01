from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

_DEPRECATED_TLS_VERSIONS = {
    "ssl2",
    "sslv2",
    "ssl3",
    "sslv3",
    "tls1",
    "tls10",
    "tls11",
    "tlsv1",
    "tlsv10",
    "tlsv11",
}


@dataclass(frozen=True)
class ProtocolExpertPolicy:
    """Bounds for explainable metadata-only protocol health findings."""

    dns_error_burst_threshold: int = 3
    http_server_error_burst_threshold: int = 3
    max_flows: int = 5_000
    max_findings: int = 1_000

    def validate(self) -> None:
        if self.dns_error_burst_threshold < 1 or self.dns_error_burst_threshold > 1_000:
            raise ValueError("DNS error-burst threshold must be between 1 and 1000.")
        if (
            self.http_server_error_burst_threshold < 1
            or self.http_server_error_burst_threshold > 1_000
        ):
            raise ValueError("HTTP server-error threshold must be between 1 and 1000.")
        if self.max_flows < 1 or self.max_flows > 50_000:
            raise ValueError("Protocol expert flow bound must be between 1 and 50000.")
        if self.max_findings < 1 or self.max_findings > 10_000:
            raise ValueError("Protocol expert finding bound must be between 1 and 10000.")


def _text(value: object) -> str:
    return str(value or "").strip()


def _normalized_tls_version(value: object) -> str:
    return "".join(character for character in _text(value).lower() if character.isalnum())


def _is_deprecated_tls_version(value: object) -> bool:
    return _normalized_tls_version(value) in _DEPRECATED_TLS_VERSIONS


def _is_dns_error(value: object) -> bool:
    if isinstance(value, int):
        return value != 0
    normalized = _text(value).upper()
    return bool(normalized and normalized not in {"0", "NOERROR"})


def _http_status(value: object) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _events(flow: dict[str, object]) -> list[dict[str, object]]:
    value = flow.get("protocol_events")
    if not isinstance(value, list):
        return []
    return [event for event in value if isinstance(event, dict)]


def _metadata(event: dict[str, object]) -> dict[str, object]:
    value = event.get("metadata")
    return value if isinstance(value, dict) else {}


def analyze_protocol_expert_findings(
    flows: Iterable[dict[str, object]],
    *,
    policy: ProtocolExpertPolicy | None = None,
) -> list[dict[str, object]]:
    """Surface bounded protocol health findings from correlated metadata.

    Findings intentionally contain only the signal, severity, flow identifier,
    observed condition, threshold, and a fixed explanation. DNS names, HTTP hosts,
    raw payloads, credentials, and arbitrary event metadata are never copied.
    """
    selected = policy or ProtocolExpertPolicy()
    selected.validate()

    records = [dict(flow) for flow in flows]
    if len(records) > selected.max_flows:
        raise ValueError(f"Protocol expert analysis accepts at most {selected.max_flows} flows.")

    findings: list[dict[str, object]] = []
    for flow in records:
        flow_id = _text(flow.get("flow_id")) or "unknown-flow"
        dns_errors = 0
        http_server_errors = 0
        deprecated_versions: set[str] = set()

        for event in _events(flow):
            event_type = _text(event.get("event_type")).lower()
            metadata = _metadata(event)
            if event_type == "tls":
                version = metadata.get("version")
                if _is_deprecated_tls_version(version):
                    deprecated_versions.add(_text(version))
            elif event_type == "dns" and _is_dns_error(metadata.get("rcode")):
                dns_errors += 1
            elif event_type == "http":
                status = _http_status(metadata.get("status_code"))
                if 500 <= status <= 599:
                    http_server_errors += 1

        for version in sorted(deprecated_versions):
            findings.append(
                {
                    "signal": "deprecated_tls_version",
                    "severity": "high",
                    "entity": flow_id,
                    "flow_ids": [] if flow_id == "unknown-flow" else [flow_id],
                    "observed": version,
                    "threshold": "TLS 1.2+",
                    "explanation": (
                        "The flow negotiated a deprecated TLS version; validate legacy "
                        "dependencies and migrate the service to TLS 1.2 or newer."
                    ),
                }
            )

        if dns_errors >= selected.dns_error_burst_threshold:
            findings.append(
                {
                    "signal": "dns_error_burst",
                    "severity": "medium",
                    "entity": flow_id,
                    "flow_ids": [] if flow_id == "unknown-flow" else [flow_id],
                    "observed": dns_errors,
                    "threshold": selected.dns_error_burst_threshold,
                    "explanation": (
                        "Repeated DNS errors occurred on this flow; validate resolver health, "
                        "stale configuration, or unexpected name-resolution behavior."
                    ),
                }
            )

        if http_server_errors >= selected.http_server_error_burst_threshold:
            findings.append(
                {
                    "signal": "http_server_error_burst",
                    "severity": "medium",
                    "entity": flow_id,
                    "flow_ids": [] if flow_id == "unknown-flow" else [flow_id],
                    "observed": http_server_errors,
                    "threshold": selected.http_server_error_burst_threshold,
                    "explanation": (
                        "Repeated HTTP 5xx responses occurred on this flow; validate upstream "
                        "service health, dependency failures, or deployment regressions."
                    ),
                }
            )

    severity_rank = {"high": 0, "medium": 1, "low": 2}
    ordered = sorted(
        findings,
        key=lambda finding: (
            severity_rank.get(_text(finding.get("severity")), 9),
            _text(finding.get("signal")),
            _text(finding.get("entity")),
            _text(finding.get("observed")),
        ),
    )
    return ordered[: selected.max_findings]
