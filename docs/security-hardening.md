# Security Hardening Notes

This document records the defensive controls used in NetWatch.

## Target safety

- Public Internet targets are blocked by validation logic.
- The app accepts only explicit RFC 1918, loopback, link-local, and IPv6 ULA ranges.
- Unspecified, multicast, reserved, and documentation targets are blocked.
- CIDR scans have a maximum host limit.
- Streamlit scans require a permission checkbox and API scans require an authorization flag.

## Local API boundary

- Wildcard CORS is disabled.
- Browser origins and Host headers use explicit local allowlists by default.
- Query and request sizes are bounded.
- Only one API network check can run at a time.
- The API should remain bound to `127.0.0.1` unless real authentication is added.

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

HTML reports escape table values before export. Markdown table separators are escaped, and Markdown reports are previewed through Streamlit without unsafe HTML.

## Container boundary

The image includes the required ping utility, runs as an unprivileged user, and
has a health check. Docker Compose binds the dashboard to localhost, drops
unneeded Linux capabilities, and uses named volumes for operational data.

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

## Remaining production requirements

For a real company deployment, add organization authentication, approved scan ranges, role-based access control, centralized logging, report approval workflow, and retention policy.
