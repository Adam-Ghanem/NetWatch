# Security Hardening Notes

This document records the defensive controls added to keep NetWatch safe for local demos and company review.

## Target safety

- Public Internet targets are blocked by validation logic.
- The app accepts only private, loopback, or link-local addresses.
- CIDR scans have a maximum host limit.
- Scan actions require a permission checkbox.

## UI safety

NetWatch uses custom Streamlit HTML for visual cards. Dynamic values are cleaned before being inserted into those cards.

The helper is implemented in:

```text
safe_text.py
```

## Export safety

CSV files can be opened in spreadsheet tools, so exported values are sanitized to reduce formula-injection risk.

The helper is implemented in:

```text
export_utils.py
```

## Report safety

HTML reports escape table values before exporting. Markdown reports are previewed through Streamlit without enabling unsafe HTML.

## AI Advisor privacy

The AI Advisor is local and rule-based:

- No external API call
- No API key
- No Internet dependency
- No scan data leaves the machine

## Local data

Generated files are ignored by Git:

```text
data/netwatch.db
data/scan_history.csv
logs/netwatch.log
```

These files can contain internal IP information and should not be shared publicly.

## Remaining production requirements

For a real company deployment, add:

- Organization authentication or SSO
- Approved scan ranges from a config file
- Role-based access control
- Centralized logging
- Report approval workflow
- Retention policy for local scan history
