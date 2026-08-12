#!/usr/bin/env python3
"""Run a bounded authenticated API benchmark and print a Markdown report."""

from __future__ import annotations

import argparse
import json
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass(frozen=True)
class Sample:
    latency_ms: float
    status: int
    error: str = ""


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((percentile / 100) * (len(ordered) - 1))))
    return ordered[index]


def _request(url: str, api_key: str) -> Sample:
    started = time.perf_counter()
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "X-NetWatch-Key": api_key} if api_key else {},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read(2_000_000)
            status = int(response.status)
            error = "" if 200 <= status < 400 else f"HTTP {status}"
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        error = f"HTTP {status}"
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        status = 0
        error = type(exc).__name__
    elapsed_ms = (time.perf_counter() - started) * 1_000
    return Sample(latency_ms=elapsed_ms, status=status, error=error)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--path", default="/api/health")
    parser.add_argument("--api-key", default="")
    parser.add_argument("--requests", type=int, default=40)
    parser.add_argument("--concurrency", type=int, default=4)
    args = parser.parse_args()
    total = max(1, min(args.requests, 500))
    concurrency = max(1, min(args.concurrency, 32))
    url = f"{args.base_url.rstrip('/')}/{args.path.lstrip('/')}"

    started = time.perf_counter()
    samples: list[Sample] = []
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(_request, url, args.api_key) for _ in range(total)]
        for future in as_completed(futures):
            samples.append(future.result())
    elapsed = max(0.001, time.perf_counter() - started)
    latencies = [sample.latency_ms for sample in samples]
    successes = sum(1 for sample in samples if 200 <= sample.status < 400)
    errors = len(samples) - successes
    error_types: dict[str, int] = {}
    for sample in samples:
        if sample.error:
            error_types[sample.error] = error_types.get(sample.error, 0) + 1

    report = {
        "base_url": args.base_url,
        "path": args.path,
        "requests": len(samples),
        "concurrency": concurrency,
        "elapsed_seconds": round(elapsed, 3),
        "throughput_per_second": round(len(samples) / elapsed, 2),
        "successes": successes,
        "errors": errors,
        "error_rate_percent": round(errors * 100 / len(samples), 2),
        "latency_ms": {
            "min": round(min(latencies), 2) if latencies else 0,
            "mean": round(statistics.mean(latencies), 2) if latencies else 0,
            "p50": round(_percentile(latencies, 50), 2),
            "p95": round(_percentile(latencies, 95), 2),
            "p99": round(_percentile(latencies, 99), 2),
            "max": round(max(latencies), 2) if latencies else 0,
        },
        "errors_by_type": error_types,
    }
    print("# NetWatch API Benchmark")
    print()
    print(f"- Target: `{report['base_url']}{report['path']}`")
    print(f"- Requests: **{report['requests']}** at concurrency **{report['concurrency']}**")
    print(f"- Throughput: **{report['throughput_per_second']} req/s**")
    print(
        f"- Success/error rate: **{successes}/{len(samples)}** / "
        f"**{report['error_rate_percent']}%**"
    )
    print()
    print("| Metric | Value |")
    print("|---|---:|")
    for key, value in report["latency_ms"].items():
        print(f"| Latency {key} (ms) | {value} |")
    print()
    print("```json")
    print(json.dumps(report, indent=2, sort_keys=True))
    print("```")
    return 0 if errors == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
