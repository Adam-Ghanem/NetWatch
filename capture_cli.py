from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from flow_export import export_flows_csv
from pcap_import import MAX_PCAP_BYTES, MAX_PCAP_PACKETS, import_pcap_metadata
from pcapng_import import import_pcapng_bytes

_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}


def analyze_capture_bytes(data: bytes, *, packet_limit: int = 1_000) -> dict[str, Any]:
    """Analyze a bounded PCAP/PCAPNG capture without retaining packet payloads."""
    if packet_limit < 1 or packet_limit > MAX_PCAP_PACKETS:
        raise ValueError(f"Packet limit must be between 1 and {MAX_PCAP_PACKETS}.")
    if len(data) > MAX_PCAP_BYTES:
        raise ValueError(f"Capture input exceeds the {MAX_PCAP_BYTES}-byte safety limit.")
    if data.startswith(_PCAPNG_MAGIC):
        return import_pcapng_bytes(data, packet_limit=packet_limit)
    if data[:4] in _PCAP_MAGICS:
        return import_pcap_metadata(data, max_packets=packet_limit)
    raise ValueError("Unsupported capture format; expected classic PCAP or PCAPNG.")


def render_capture_result(
    result: dict[str, Any],
    *,
    output_format: str = "json",
    flow_limit: int = 100,
) -> bytes:
    """Render metadata-only capture analysis as JSON or formula-safe CSV."""
    if output_format == "json":
        payload = dict(result)
        payload["payload_retained"] = False
        return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    if output_format == "csv":
        flows = result.get("flows")
        flow_rows = flows if isinstance(flows, list) else []
        return export_flows_csv(
            [dict(item) for item in flow_rows if isinstance(item, dict)],
            limit=flow_limit,
        )
    raise ValueError("Output format must be 'json' or 'csv'.")


def _read_capture(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_PCAP_BYTES:
        raise ValueError(f"Capture input exceeds the {MAX_PCAP_BYTES}-byte safety limit.")
    return path.read_bytes()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netwatch-capture",
        description="Bounded metadata-only offline PCAP/PCAPNG analysis for NetWatch.",
    )
    parser.add_argument("capture", type=Path, help="PCAP or PCAPNG file to analyze")
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        dest="output_format",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--packet-limit",
        type=int,
        default=1_000,
        help=f"Maximum packets to inspect (1..{MAX_PCAP_PACKETS})",
    )
    parser.add_argument(
        "--flow-limit",
        type=int,
        default=100,
        help="Maximum flow rows emitted by CSV export (1..1000)",
    )
    parser.add_argument("--output", type=Path, help="Write output to a file instead of stdout")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        data = _read_capture(args.capture)
        result = analyze_capture_bytes(data, packet_limit=args.packet_limit)
        rendered = render_capture_result(
            result,
            output_format=args.output_format,
            flow_limit=args.flow_limit,
        )
        if args.output is not None:
            args.output.write_bytes(rendered)
        else:
            sys.stdout.buffer.write(rendered)
    except (OSError, ValueError) as exc:
        print(f"netwatch-capture: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
