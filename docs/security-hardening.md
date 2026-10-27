# Security Hardening Notes

This document records the defensive controls used in NetWatch.

## Target safety

- Public Internet targets are blocked by validation logic.
- The app accepts only private, loopback, or link-local addresses.
- CIDR scans have a maximum host limit.
- Scan actions require a permission checkbox.
- API rate, concurrency, inventory, worker, and timeout inputs have upper bounds.
- Scheduled policies accept only the same validated private CIDRs and have a 15-minute minimum interval.
- Policy scope is immutable after Admin approval; changed scope requires a new approval record.
- Scheduled execution is opt-in and shares the normal scan semaphore.
- Active bounded maintenance windows are checked before scheduler claims and manual policy runs.

## API boundary

- Protected endpoints require a non-placeholder Admin, Operator, or Viewer key of at least 32 characters.
- Failed API-key and OIDC authentication attempts are counted in a bounded, in-memory sliding window before credential/token validation. Defaults: **120 failed attempts per 60 seconds per ASGI client peer**, with a limit of 4,096 peer buckets and a shared overflow budget. Requests after the limit return HTTP `429` and a `Retry-After` header. Successful requests and infrastructure errors (`503`) do not add failures; health endpoints do not use this auth limiter. No presented API keys or bearer tokens are recorded.
- This defense is **single-process**, not distributed, and can temporarily block legitimate users sharing a proxy/NAT address if that peer is abused. An approved reverse proxy must enforce its own per-client abuse controls and tightly restrict which addresses are allowed to provide forwarded client identity; do not rely on untrusted `X-Forwarded-For` input. The authenticated `/api/metrics` endpoint exports fixed, label-free totals for failed attempts and blocked requests, plus the active peer-bucket gauge; it never exports source IPs, keys, or tokens. Configurable with `NETWATCH_AUTH_FAILURE_LIMIT`, `NETWATCH_AUTH_FAILURE_WINDOW_SECONDS`, and `NETWATCH_AUTH_FAILURE_MAX_PEERS`.
- Viewer, Operator, and Admin capabilities are enforced on the server; dashboard disabling is only a usability layer.
- CORS origins and HTTP Host headers use explicit local allowlists.
- Wildcard-only allowlists fall back to safe local defaults.
- API write requests are limited to **256 KiB** before body parsing, including streamed requests without `Content-Length`. Offline PCAP/PCAPNG uploads retain their separate **32 MiB** ceiling. Over-limit requests return HTTP `413` and malformed or duplicate `Content-Length` headers return HTTP `400`. Production reverse proxies should enforce their own matching size and timeout limits, since upstream buffering can happen before the application receives data.

## UI safety

The supported dashboard is the same-origin FastAPI frontend. Role keys stay in browser session storage, and approved network actions require server-enforced authorization. Historical Streamlit code remains in the source tree but is intentionally excluded from installation and Docker Compose: its published Pillow < 13 constraint prevents applying the critical fixes in Pillow 13.0.0. Do not run the legacy application or bypass the dependency audit until compatible patched upstream releases exist.

`safe_text.py` continues to sanitize report and legacy-compatible text.

## Export safety

CSV exports are sanitized to reduce spreadsheet formula-injection risk.

Related file:

```text
export_utils.py
```

## Report safety

HTML reports escape table values before export. Markdown report cells escape table delimiters, backslashes, and line breaks.

## Advisor and intelligence privacy

The Risk Advisor is a local rule-based module. It uses the current dashboard data and generated inventory files on the same machine.

Optional NetWatch Intelligence is server-side only. Before a provider call, NetWatch creates a bounded aggregate snapshot and excludes private addresses, CIDRs, hostnames, asset ownership/location fields, notes, and raw event details. The provider key is read from runtime environment only, and `.env` is excluded from both Git and Docker build context. Requests use storage-disabled structured output, no tools, a key-separated opaque safety identifier, a no-redirect provider transport, bounded time/output, separate rate/concurrency limits, an atomic day-keyed budget independent of cache retention, and a local cache. The dashboard attaches role keys only to same-origin API requests. Provider failure does not disable the local advisor or core monitoring.

## Local data

Generated files are ignored by Git:

```text
data/netwatch.db
data/scan_history.csv
logs/netwatch.log
```

These files can contain internal IP information and should not be shared publicly.

Asset/company context, approved policies, maintenance windows, operational cases, operations audit records, durable outbox events, and idempotent jobs are stored in SQLite in the compatibility and single-tenant modes. Audit, case, policy, maintenance, outbox, and job retention are bounded by their worker/event-sink policies, and raw role keys are never written to audit details. Unresolved repeats are deduplicated, closure requires a resolution note, and outbox/job claims use bounded leases with dedupe keys and retry limits.

The authenticated metrics endpoint exports only fixed numeric counters. It does not use target, IP, hostname, owner, or free-text labels. It includes outbox pending/dead-letter and job active/failed gauges without payloads. Intelligence metrics are counts only and contain no model prompts, responses, safety identifiers, user identifiers, or targets.

Admin snapshot downloads use SQLite's backup API instead of copying live database and WAL files. Snapshots are sensitive and must be stored in an approved encrypted location. Restore remains an offline, deployment-owned procedure so the API cannot destructively replace its live database.

## Remaining production requirements

For a remote or multi-user production deployment, place NetWatch behind an approved OIDC-aware TLS gateway, configure dedicated least-privilege groups, inject managed secrets, export audit/log evidence to append-only storage, configure provider spend/rate controls, automate encrypted off-host backups with restore drills, and complete monitoring, report approval, AI/privacy, retention, and deployment security reviews. The `shared_service` mode fails closed until external workers with leader election, shared transactional storage, distributed rate/quota state, object storage, tenant/resource policy enforcement, and migration tests are deployed. Selecting the mode alone never enables active-active behavior.
