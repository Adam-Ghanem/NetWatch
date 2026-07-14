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

## Risk Advisor privacy

The Risk Advisor is a local rule-based module. It uses the current dashboard data and generated inventory files on the same machine.

## Local data

Generated files are ignored by Git:

```text
data/netwatch.db
data/scan_history.csv
logs/netwatch.log
```

These files can contain internal IP information and should not be shared publicly.

Asset/company context, approved policies, operational alerts, and operations audit records are stored in SQLite. Audit and alert retention are bounded, and raw role keys are never written to audit details.

Admin snapshot downloads use SQLite's backup API instead of copying live database and WAL files. Snapshots are sensitive and must be stored in an approved encrypted location. Restore remains an offline, deployment-owned procedure so the API cannot destructively replace its live database.

## Remaining production requirements

For a remote or multi-user production deployment, add SSO/OIDC with individual identities, fine-grained authorization, managed secrets, centralized tamper-resistant logging, TLS, an external scheduler with leader election, automated encrypted off-host backups with restore drills, monitoring, report approval workflow, and a formal retention policy.
