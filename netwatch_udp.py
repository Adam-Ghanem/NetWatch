from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections.abc import Sequence

from udp_service_scanner import scan_udp_services

_ALLOWED_SERVICES = ("dns", "ntp")
_ALLOWED_FORMATS = ("json", "csv")


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
        help="UDP service profile to check; may be supplied twice (default: dns and ntp)",
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


def _csv_text(rows: list[dict[str, object]]) -> str:
    if not rows:
        return ""
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.authorized:
        parser.error("--authorized is required for UDP service checks")

    services = tuple(args.services) if args.services else _ALLOWED_SERVICES
    try:
        rows = scan_udp_services(args.target, services=services, timeout=args.timeout)
    except ValueError as exc:
        parser.error(str(exc))

    if args.format == "csv":
        sys.stdout.write(_csv_text(rows))
    else:
        json.dump({"count": len(rows), "items": rows}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
