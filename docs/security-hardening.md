# Security Hardening Notes

This document records the defensive controls used in NetWatch.

## Target safety

- Public Internet targets are blocked by validation logic.
- The app accepts only private, loopback, or link-local addresses.
- CIDR scans have a maximum host limit.
- Scan actions require a permission checkbox.
- API rate, concurrency, inventory, worker, and timeout inputs have upper bounds.

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

Asset/company context and operations audit records are stored in SQLite. Audit retention is bounded, and raw role keys are never written to audit details.

## Remaining production requirements

For a remote or multi-user production deployment, add SSO/OIDC with individual identities, approved scan ranges, fine-grained authorization, managed secrets, centralized tamper-resistant logging, TLS, backups, monitoring, report approval workflow, and a formal retention policy.
