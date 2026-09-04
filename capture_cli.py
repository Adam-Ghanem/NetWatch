from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from flow_export import export_flows_csv, export_flows_ndjson
from pcap_import import MAX_PCAP_BYTES, MAX_PCAP_PACKETS, import_pcap_metadata
from pcapng_import import import_pcapng_bytes
from traffic_flow_controls import TrafficFlowControls, apply_traffic_flow_controls

_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}


def analyze_capture_bytes(
    data: bytes,
    *,
    packet_limit: int = 1_000,
    controls: TrafficFlowControls | None = None,
) -> dict[str, Any]:
    """Analyze a bounded PCAP/PCAPNG capture without retaining packet payloads."""
    if packet_limit < 1 or packet_limit > MAX_PCAP_PACKETS:
        raise ValueError(f"Packet limit must be between 1 and {MAX_PCAP_PACKETS}.")
    if len(data) > MAX_PCAP_BYTES:
        raise ValueError(f"Capture input exceeds the {MAX_PCAP_BYTES}-byte safety limit.")
    if data.startswith(_PCAPNG_MAGIC):
        result = import_pcapng_bytes(data, packet_limit=packet_limit)
    elif data[:4] in _PCAP_MAGICS:
        result = import_pcap_metadata(data, max_packets=packet_limit)
    else:
        raise ValueError("Unsupported capture format; expected classic PCAP or PCAPNG.")
    return apply_traffic_flow_controls(result, controls or TrafficFlowControls())


def build_capture_preview(result: dict[str, Any], *, capture_bytes: int) -> dict[str, Any]:
    """Build a compact, metadata-only capture preview without packet or flow rows."""
    preview: dict[str, Any] = {
        "source": result.get("source", "capture"),
        "capture_bytes": max(0, int(capture_bytes)),
        "captured_packets": int(result.get("captured_packets", 0) or 0),
        "flow_count": int(result.get("flow_count", 0) or 0),
        "duration_seconds": int(result.get("duration_seconds", 0) or 0),
        "protocols": result.get("protocols", []),
        "truncated_by_limit": bool(result.get("truncated_by_limit", False)),
        "payload_retained": False,
    }
    for key in ("pcap_version", "linktype", "processed_records"):
        if key in result:
            preview[key] = result[key]
    return preview


def render_capture_preview(result: dict[str, Any], *, capture_bytes: int) -> bytes:
    """Render a deterministic JSON preview suitable for pre-analysis inspection."""
    preview = build_capture_preview(result, capture_bytes=capture_bytes)
    return (json.dumps(preview, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def render_capture_result(
    result: dict[str, Any],
    *,
    output_format: str = "json",
    flow_limit: int = 100,
) -> bytes:
    """Render metadata-only capture analysis as JSON, NDJSON, or formula-safe CSV."""
    if output_format == "json":
        payload = dict(result)
        payload["payload_retained"] = False
        return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    flows = result.get("flows")
    flow_rows = (
        [dict(item) for item in flows if isinstance(item, dict)] if isinstance(flows, list) else []
    )
    if output_format == "ndjson":
        return export_flows_ndjson(flow_rows, limit=flow_limit)
    if output_format == "csv":
        return export_flows_csv(flow_rows, limit=flow_limit)
    raise ValueError("Output format must be 'json', 'ndjson', or 'csv'.")


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
        choices=("json", "ndjson", "csv"),
        default="json",
        dest="output_format",
        help="Output format (default: json)",
    )
    parser.add_argument(
        "--preview",
        action="store_true",
        help="Emit compact JSON file/capture metadata without packet or flow rows",
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
        help="Maximum matched flow rows (1..1000; default: 100)",
    )
    parser.add_argument(
        "--display-filter",
        default="",
        help="Safe metadata-only flow display filter expression",
    )
    parser.add_argument("--flow-ip", default="", help="Match an exact flow endpoint IP")
    parser.add_argument("--flow-protocol", default="", help="Match a flow protocol")
    parser.add_argument("--flow-service", default="", help="Match a service hint")
    parser.add_argument("--flow-state", default="", help="Match a canonical flow state")
    parser.add_argument(
        "--min-bytes",
        type=int,
        default=0,
        help="Require at least this many observed flow bytes",
    )
    parser.add_argument(
        "--sort-by",
        choices=("bytes", "packets", "duration", "recent"),
        default="bytes",
        help="Flow ranking order (default: bytes)",
    )
    parser.add_argument("--output", type=Path, help="Write output to a file instead of stdout")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.preview and args.output_format != "json":
            raise ValueError("Preview mode only supports JSON output.")
        data = _read_capture(args.capture)
        controls = TrafficFlowControls(
            display_filter=args.display_filter,
            ip_address=args.flow_ip,
            protocol=args.flow_protocol,
            service=args.flow_service,
            state=args.flow_state,
            min_bytes=args.min_bytes,
            sort_by=args.sort_by,
            limit=args.flow_limit,
        )
        result = analyze_capture_bytes(
            data,
            packet_limit=args.packet_limit,
            controls=controls,
        )
        if args.preview:
            rendered = render_capture_preview(result, capture_bytes=len(data))
        else:
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
