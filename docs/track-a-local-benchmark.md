# Track A Local Staging Benchmark

**Date:** 2026-08-12  
**Environment:** Isolated local Uvicorn process on `127.0.0.1:18000`, temporary SQLite data directory, one application process, localhost only.  
**Rate-limit setting:** Raised to 1,000 requests/minute only for this controlled benchmark; normal deployment protection remains unchanged.  
**Scope:** Authenticated inventory, Markdown/PDF reports, retention status, and public health. No network scan was started.

## Results

===== health =====
# NetWatch API Benchmark

- Target: `http://127.0.0.1:18000/api/health`
- Requests: **60** at concurrency **8**
- Throughput: **229.83 req/s**
- Success/error rate: **60/60** / **0.0%**

| Metric | Value |
|---|---:|
| Latency min (ms) | 1.18 |
| Latency mean (ms) | 34.0 |
| Latency p50 (ms) | 6.66 |
| Latency p95 (ms) | 224.37 |
| Latency p99 (ms) | 226.93 |
| Latency max (ms) | 228.32 |

```json
{
  "base_url": "http://127.0.0.1:18000",
  "concurrency": 8,
  "elapsed_seconds": 0.261,
  "error_rate_percent": 0.0,
  "errors": 0,
  "errors_by_type": {},
  "latency_ms": {
    "max": 228.32,
    "mean": 34.0,
    "min": 1.18,
    "p50": 6.66,
    "p95": 224.37,
    "p99": 226.93
  },
  "path": "/api/health",
  "requests": 60,
  "successes": 60,
  "throughput_per_second": 229.83
}
```

===== inventory =====
# NetWatch API Benchmark

- Target: `http://127.0.0.1:18000/api/inventory`
- Requests: **40** at concurrency **4**
- Throughput: **161.8 req/s**
- Success/error rate: **40/40** / **0.0%**

| Metric | Value |
|---|---:|
| Latency min (ms) | 5.27 |
| Latency mean (ms) | 24.05 |
| Latency p50 (ms) | 13.15 |
| Latency p95 (ms) | 116.07 |
| Latency p99 (ms) | 129.07 |
| Latency max (ms) | 129.07 |

```json
{
  "base_url": "http://127.0.0.1:18000",
  "concurrency": 4,
  "elapsed_seconds": 0.247,
  "error_rate_percent": 0.0,
  "errors": 0,
  "errors_by_type": {},
  "latency_ms": {
    "max": 129.07,
    "mean": 24.05,
    "min": 5.27,
    "p50": 13.15,
    "p95": 116.07,
    "p99": 129.07
  },
  "path": "/api/inventory",
  "requests": 40,
  "successes": 40,
  "throughput_per_second": 161.8
}
```

===== markdown =====
# NetWatch API Benchmark

- Target: `http://127.0.0.1:18000/api/reports/markdown`
- Requests: **40** at concurrency **4**
- Throughput: **42.75 req/s**
- Success/error rate: **40/40** / **0.0%**

| Metric | Value |
|---|---:|
| Latency min (ms) | 34.89 |
| Latency mean (ms) | 92.38 |
| Latency p50 (ms) | 77.56 |
| Latency p95 (ms) | 178.83 |
| Latency p99 (ms) | 210.35 |
| Latency max (ms) | 210.35 |

```json
{
  "base_url": "http://127.0.0.1:18000",
  "concurrency": 4,
  "elapsed_seconds": 0.936,
  "error_rate_percent": 0.0,
  "errors": 0,
  "errors_by_type": {},
  "latency_ms": {
    "max": 210.35,
    "mean": 92.38,
    "min": 34.89,
    "p50": 77.56,
    "p95": 178.83,
    "p99": 210.35
  },
  "path": "/api/reports/markdown",
  "requests": 40,
  "successes": 40,
  "throughput_per_second": 42.75
}
```

===== pdf =====
# NetWatch API Benchmark

- Target: `http://127.0.0.1:18000/api/reports/pdf`
- Requests: **40** at concurrency **4**
- Throughput: **35.43 req/s**
- Success/error rate: **40/40** / **0.0%**

| Metric | Value |
|---|---:|
| Latency min (ms) | 61.23 |
| Latency mean (ms) | 110.95 |
| Latency p50 (ms) | 89.28 |
| Latency p95 (ms) | 211.86 |
| Latency p99 (ms) | 230.34 |
| Latency max (ms) | 230.34 |

```json
{
  "base_url": "http://127.0.0.1:18000",
  "concurrency": 4,
  "elapsed_seconds": 1.129,
  "error_rate_percent": 0.0,
  "errors": 0,
  "errors_by_type": {},
  "latency_ms": {
    "max": 230.34,
    "mean": 110.95,
    "min": 61.23,
    "p50": 89.28,
    "p95": 211.86,
    "p99": 230.34
  },
  "path": "/api/reports/pdf",
  "requests": 40,
  "successes": 40,
  "throughput_per_second": 35.43
}
```

===== retention =====
# NetWatch API Benchmark

- Target: `http://127.0.0.1:18000/api/retention/status`
- Requests: **40** at concurrency **4**
- Throughput: **142.99 req/s**
- Success/error rate: **40/40** / **0.0%**

| Metric | Value |
|---|---:|
| Latency min (ms) | 5.04 |
| Latency mean (ms) | 27.52 |
| Latency p50 (ms) | 16.6 |
| Latency p95 (ms) | 123.95 |
| Latency p99 (ms) | 134.5 |
| Latency max (ms) | 134.5 |

```json
{
  "base_url": "http://127.0.0.1:18000",
  "concurrency": 4,
  "elapsed_seconds": 0.28,
  "error_rate_percent": 0.0,
  "errors": 0,
  "errors_by_type": {},
  "latency_ms": {
    "max": 134.5,
    "mean": 27.52,
    "min": 5.04,
    "p50": 16.6,
    "p95": 123.95,
    "p99": 134.5
  },
  "path": "/api/retention/status",
  "requests": 40,
  "successes": 40,
  "throughput_per_second": 142.99
}
```
