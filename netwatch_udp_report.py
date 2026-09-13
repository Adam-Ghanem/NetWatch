from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from netwatch_udp import _run_summary

_SUMMARY_SCHEMA = "netwatch.udp-service-evidence-summary"
_SUMMARY_SCHEMA_VERSION = 1
_MAX_INPUT_BYTES = 5 * 1024 * 1024
_MAX_RECORDS = 10_000
_FORMATS = ("auto", "json", "jsonl", "csv")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netwatch-udp-report",
        description=(
            "Summarize previously exported NetWatch UDP evidence without sending network traffic. "
            "Input is bounded to 5 MiB and 10,000 records."
        ),
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Evidence file to summarize, or '-' to read stdin (default: stdin)",
    )
    parser.add_argument(
        "--format",
        choices=_FORMATS,
        default="auto",
        help="Input format; auto detects NetWatch JSON, JSONL, or CSV (default: auto)",
    )
    return parser


def _bounded_text(path: str) -> str:
    if path == "-":
        data = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    else:
        with Path(path).open("rb") as handle:
            data = handle.read(_MAX_INPUT_BYTES + 1)
    if len(data) > _MAX_INPUT_BYTES:
        raise ValueError("UDP evidence input exceeds the 5 MiB reporting limit")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("UDP evidence input must be UTF-8 text") from exc


def _validate_rows(rows: object) -> list[dict[str, object]]:
    if not isinstance(rows, list):
        raise ValueError("UDP evidence must contain a list of records")
    if len(rows) > _MAX_RECORDS:
        raise ValueError("UDP evidence exceeds the 10,000-record reporting limit")
    validated: list[dict[str, object]] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"UDP evidence record {index} must be an object")
        validated.append(dict(row))
    return validated


def _rows_from_json(text: str) -> list[dict[str, object]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON UDP evidence") from exc
    if isinstance(payload, dict):
        if "items" not in payload:
            raise ValueError("NetWatch JSON evidence envelope must contain an 'items' list")
        return _validate_rows(payload["items"])
    return _validate_rows(payload)


def _rows_from_jsonl(text: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        if len(rows) >= _MAX_RECORDS:
            raise ValueError("UDP evidence exceeds the 10,000-record reporting limit")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL at line {line_number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"UDP evidence JSONL line {line_number} must be an object")
        rows.append(dict(row))
    return rows


def _rows_from_csv(text: str) -> list[dict[str, object]]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise ValueError("UDP evidence CSV must contain a header row")
    rows: list[dict[str, object]] = []
    for row in reader:
        if len(rows) >= _MAX_RECORDS:
            raise ValueError("UDP evidence exceeds the 10,000-record reporting limit")
        rows.append(dict(row))
    return rows


def _detect_format(text: str) -> str:
    stripped = text.lstrip()
    if stripped.startswith("["):
        return "json"
    if stripped.startswith("{"):
        first_line = next((line.strip() for line in text.splitlines() if line.strip()), "")
        try:
            json.loads(text)
        except json.JSONDecodeError:
            try:
                first_value = json.loads(first_line)
            except json.JSONDecodeError:
                return "csv"
            return "jsonl" if isinstance(first_value, dict) else "json"
        return "json"
    return "csv"


def _load_rows(text: str, input_format: str) -> list[dict[str, object]]:
    selected = _detect_format(text) if input_format == "auto" else input_format
    if selected == "json":
        return _rows_from_json(text)
    if selected == "jsonl":
        return _rows_from_jsonl(text)
    if selected == "csv":
        return _rows_from_csv(text)
    raise ValueError(f"Unsupported UDP evidence format: {selected}")


def _summary_envelope(rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema": _SUMMARY_SCHEMA,
        "schema_version": _SUMMARY_SCHEMA_VERSION,
        "count": len(rows),
        "summary": _run_summary(rows),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        text = _bounded_text(args.input)
        rows = _load_rows(text, args.format)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    json.dump(_summary_envelope(rows), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
