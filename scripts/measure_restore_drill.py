"""Offline timing evidence for an operator-controlled restore drill.

This reports observed intervals only; it never performs a restore or network request.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone


def parse_timestamp(value: str) -> datetime:
    """Require an explicitly timezone-aware ISO-8601 timestamp."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be ISO-8601 with timezone") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def measure(last_durable: str, failure: str, ready: str) -> dict[str, object]:
    """Calculate observed RPO/RTO proxies from operator-supplied UTC instants."""
    durable_at = parse_timestamp(last_durable)
    failure_at = parse_timestamp(failure)
    ready_at = parse_timestamp(ready)
    if durable_at > failure_at:
        raise ValueError("last durable evidence cannot follow failure")
    if ready_at < failure_at:
        raise ValueError("readiness cannot precede failure")
    return {
        "last_durable_at": durable_at.isoformat(),
        "failure_at": failure_at.isoformat(),
        "ready_at": ready_at.isoformat(),
        "observed_rpo_seconds": (failure_at - durable_at).total_seconds(),
        "observed_rto_seconds": (ready_at - failure_at).total_seconds(),
        "scope": "operator-supplied isolated drill timestamps; not production SLA",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--last-durable", required=True)
    parser.add_argument("--failure", required=True)
    parser.add_argument("--ready", required=True)
    args = parser.parse_args()
    try:
        report = measure(args.last_durable, args.failure, args.ready)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
