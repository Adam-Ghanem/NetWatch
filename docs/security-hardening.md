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
- Viewer, Operator, and Admin capabilities are enforced on the server; dashboard disabling is only a usability layer.
- CORS origins and HTTP Host headers use explicit local allowlists.
- Wildcard-only allowlists fall back to safe local defaults.

## UI safety

Custom Streamlit HTML cards use cleaned dynamic values.

Related file:

```text
safe_text.py
```

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

Asset/company context, approved policies, maintenance windows, operational cases, and operations audit records are stored in SQLite. Audit, case, policy, and maintenance retention are bounded, and raw role keys are never written to audit details. Unresolved repeats are deduplicated, and closure requires a resolution note.

The authenticated metrics endpoint exports only fixed numeric counters. It does not use target, IP, hostname, owner, or free-text labels. Intelligence metrics are counts only and contain no model prompts, responses, safety identifiers, user identifiers, or targets.

Admin snapshot downloads use SQLite's backup API instead of copying live database and WAL files. Snapshots are sensitive and must be stored in an approved encrypted location. Restore remains an offline, deployment-owned procedure so the API cannot destructively replace its live database.

## Remaining production requirements

For a remote or multi-user production deployment, add SSO/OIDC with individual identities, fine-grained authorization, managed secrets, provider project spend/rate controls, centralized tamper-resistant logging, TLS, an external scheduler with leader election, automated encrypted off-host backups with restore drills, monitoring, report approval workflow, AI/privacy review, and a formal retention policy.
