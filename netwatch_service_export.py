from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from service_evidence import MAX_SERVICE_EVIDENCE_RECORDS
from service_evidence_query import export_recent_service_evidence


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Export persisted NetWatch service evidence without performing network activity."
        )
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        dest="output_format",
        help="Stable export format (default: json).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        choices=range(1, MAX_SERVICE_EVIDENCE_RECORDS + 1),
        metavar=f"1..{MAX_SERVICE_EVIDENCE_RECORDS}",
        help="Maximum persisted findings to export (default: 200).",
    )
    parser.add_argument(
        "--scan-run-id",
        type=int,
        default=None,
        help="Restrict output to one positive scan run id.",
    )
    parser.add_argument(
        "--ip-address",
        default=None,
        help="Restrict output to one persisted IPv4 or IPv6 address.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.scan_run_id is not None and args.scan_run_id < 1:
        parser.error("--scan-run-id must be a positive integer")

    try:
        output = export_recent_service_evidence(
            output_format=args.output_format,
            limit=args.limit,
            scan_run_id=args.scan_run_id,
            ip_address=args.ip_address,
        )
    except ValueError as exc:
        parser.error(str(exc))

    sys.stdout.write(output)
    if output and not output.endswith("\n"):
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
