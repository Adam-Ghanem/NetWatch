from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import sys
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone

from udp_service_scanner import scan_udp_services

_ALLOWED_SERVICES = ("dns", "ntp")
_ALLOWED_FORMATS = ("json", "jsonl", "csv")
_EVIDENCE_SCHEMA = "netwatch.udp-service-evidence"
_EVIDENCE_SCHEMA_VERSION = 1
_EVIDENCE_METADATA_FIELDS = frozenset(
    {
        "Evidence Schema",
        "Schema Version",
        "Evidence ID",
        "Service Key",
        "Run ID",
        "Observed At",
        "Target",
        "Destination Address",
        "Destination Port",
        "Address Family",
        "Network Transport",
        "Network Protocol",
        "Evidence Source",
        "Event Type",
        "Evidence Semantics",
    }
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netwatch-udp",
        description=(
            "Run tightly bounded UDP service checks against one authorized local target. "
            "Only DNS and NTP profiles are supported; each selected profile sends one datagram "
            "with no retries."
        ),
    )
    parser.add_argument("target", help="Authorized private/local IPv4 or IPv6 target")
    parser.add_argument(
        "--service",
        dest="services",
        action="append",
        choices=_ALLOWED_SERVICES,
        help="UDP service profile to check; select each distinct profile at most once",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.35,
        help="Per-profile timeout in seconds, bounded to 0.05..1.0 (default: 0.35)",
    )
    parser.add_argument(
        "--format",
        choices=_ALLOWED_FORMATS,
        default="json",
        help="Machine-readable output format (default: json)",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Confirm you are authorized to assess the target",
    )
    return parser


def _canonical_target(target: str) -> str:
    stripped = target.strip()
    host, separator, scope = stripped.partition("%")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return stripped
    canonical = address.compressed
    if separator:
        return f"{canonical}%{scope}"
    return canonical


def _address_family(target: str) -> str:
    host = target.strip().partition("%")[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "Unknown"
    return "IPv6" if address.version == 6 else "IPv4"


def _evidence_semantics(status: object) -> str:
    return {
        "Open": "response_observed",
        "Closed": "explicit_refusal",
        "Open|Filtered": "no_response",
        "Blocked": "validation_blocked",
    }.get(str(status), "unknown")


def _network_protocol(service: object) -> str:
    protocol = str(service or "").strip().lower()
    return protocol if protocol in _ALLOWED_SERVICES else "unknown"


def _service_key(*, target: str, protocol: str, port: object) -> str:
    identity = f"{_EVIDENCE_SCHEMA}:{_canonical_target(target)}:{protocol}:{port}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, identity))


def _evidence_id(
    *,
    run_id: str,
    target: str,
    protocol: str,
    port: object,
) -> str:
    identity = f"{_EVIDENCE_SCHEMA}:{run_id}:{_canonical_target(target)}:{protocol}:{port}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, identity))


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _run_id() -> str:
    return str(uuid.uuid4())


def _normalized_rows(
    target: str,
    rows: list[dict[str, object]],
    *,
    observed_at: str | None = None,
    run_id: str | None = None,
) -> list[dict[str, object]]:
    family = _address_family(target)
    timestamp = observed_at or _utc_timestamp()
    correlation_id = run_id or _run_id()
    normalized: list[dict[str, object]] = []
    for row in rows:
        protocol = _network_protocol(row.get("Service"))
        port = row.get("Port")
        scanner_evidence = {
            key: value for key, value in row.items() if key not in _EVIDENCE_METADATA_FIELDS
        }
        normalized.append(
            {
                "Evidence Schema": _EVIDENCE_SCHEMA,
                "Schema Version": _EVIDENCE_SCHEMA_VERSION,
                "Evidence ID": _evidence_id(
                    run_id=correlation_id,
                    target=target,
                    protocol=protocol,
                    port=port,
                ),
                "Service Key": _service_key(target=target, protocol=protocol, port=port),
                "Run ID": correlation_id,
                "Observed At": timestamp,
                "Target": target,
                "Destination Address": target,
                "Destination Port": port,
                "Address Family": family,
                "Network Transport": "udp",
                "Network Protocol": protocol,
                "Evidence Source": "active_udp_probe",
                "Event Type": "udp_service_evidence",
                "Evidence Semantics": _evidence_semantics(row.get("Status")),
                **scanner_evidence,
            }
        )
    return normalized


def _csv_text(rows: list[dict[str, object]]) -> str:
    if not rows:
        return ""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def _jsonl_text(rows: list[dict[str, object]]) -> str:
    if not rows:
        return ""
    return "".join(f"{json.dumps(row, separators=(',', ':'))}\n" for row in rows)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.authorized:
        parser.error("--authorized is required for UDP service checks")

    services = tuple(args.services) if args.services else _ALLOWED_SERVICES
    if len(services) != len(set(services)):
        parser.error("UDP service profiles must be unique")

    try:
        rows = scan_udp_services(args.target, services=services, timeout=args.timeout)
    except ValueError as exc:
        parser.error(str(exc))

    observed_at = _utc_timestamp()
    run_id = _run_id()
    normalized_rows = _normalized_rows(
        args.target,
        rows,
        observed_at=observed_at,
        run_id=run_id,
    )
    if args.format == "csv":
        sys.stdout.write(_csv_text(normalized_rows))
    elif args.format == "jsonl":
        sys.stdout.write(_jsonl_text(normalized_rows))
    else:
        json.dump(
            {
                "schema": _EVIDENCE_SCHEMA,
                "schema_version": _EVIDENCE_SCHEMA_VERSION,
                "run_id": run_id,
                "observed_at": observed_at,
                "target": args.target,
                "address_family": _address_family(args.target),
                "count": len(normalized_rows),
                "items": normalized_rows,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
