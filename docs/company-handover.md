# Company Handover Notes

## Project name

NetWatch

## Purpose

NetWatch is a local network visibility dashboard for authorized internal networks. It helps a technical team quickly check local hosts, review common exposed services, keep a small asset inventory, and export lightweight reports.

## Current scope

NetWatch currently focuses on:

- Local/private IP address checks
- Host availability checks
- Local CIDR ping sweeps
- Common TCP port audits
- Exposure scoring
- Asset inventory saved in SQLite
- Markdown and HTML report exports

## What NetWatch is not

NetWatch is not designed for:

- Public Internet scanning
- Exploitation
- Password attacks
- Stealth scanning
- Vulnerability exploitation
- Centralized asset management

## Suggested demo flow

1. Open the dashboard.
2. Go to **Network Tools** and explain the CIDR range.
3. Run **Host Check** for the router or a test machine.
4. Run **Network Scan** on a small authorized range.
5. Run **Port Audit** on one known internal IP.
6. Open **Inventory** to show saved assets.
7. Open **Reports** and export HTML or Markdown.
8. Explain the safety limits and local-only design.

## Files to mention

- `app.py`: Streamlit interface
- `security.py`: local/private target validation
- `risk_engine.py`: exposure score logic
- `inventory_store.py`: SQLite inventory
- `report_builder.py`: Markdown/HTML reports
- `docs/architecture.md`: technical architecture notes
- `docs/deployment.md`: run/deploy guide

## Improvement ideas for a company version

- Add company login or SSO
- Add role-based access control
- Add scheduled scans for approved ranges
- Add PDF reports
- Add device vendor lookup
- Add asset owner and location fields
- Add centralized logging
- Add encrypted database backups
