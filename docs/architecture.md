# NetWatch Architecture

NetWatch v1.2 is a local-first defensive network visibility application. The professional dashboard and role-protected API are served by one FastAPI process, while the older Streamlit interface remains available only as an optional legacy profile.

## Runtime flow

```text
Browser dashboard (`frontend/`)
          |
          | Same-origin HTTPS/HTTP requests
          v
FastAPI application (`backend/main.py`)
          |
          +--> Role keys, rate limits, authorization confirmation
          |
          +--> IPv4/CIDR validation (`security.py`)
          |
          +--> Host discovery and service review
          |      - `ping_checker.py`
          |      - `network_scanner.py`
          |      - `host_profiler.py`
          |      - `port_scanner.py`
          |
          +--> Exposure analysis
          |      - `risk_engine.py`
          |      - `advisory_engine.py`
          |
          +--> SQLite inventory, company context, changes, audit log (`inventory_store.py`)
          |
          +--> Markdown/HTML reports (`report_builder.py`)
```

## User interfaces

### Primary interface

The production-style dashboard is stored in `frontend/` and served at:

```text
http://127.0.0.1:8000
```

It provides:

- Secure API-key connection screen
- Admin, Operator, and Viewer capabilities
- Overview metrics and recent checks
- Authorized local CIDR discovery
- Single-host profiling
- Common TCP service audit
- Persistent asset inventory
- Asset ownership, department, location, criticality, and notes
- Scan-to-scan asset change history
- Operations audit log and inventory CSV export
- Local Risk Advisor
- Markdown and HTML report downloads

### Legacy interface

`app.py` contains the original Streamlit dashboard. It can still be started explicitly for comparison or demonstrations:

```bash
docker compose --profile legacy up streamlit
```

It is not the default deployment path.

## Main modules

- `backend/main.py`: FastAPI routes, role authorization, security headers, rate limits, scan concurrency, and frontend hosting.
- `frontend/index.html`: accessible dashboard structure.
- `frontend/styles.css`: responsive visual system.
- `frontend/app.js`: API client, dashboard state, scan workflows, rendering, and report downloads.
- `security.py`: explicit local IPv4 validation, scan-size limits, and service review guidance.
- `network_scanner.py`: local CIDR host discovery.
- `host_profiler.py`: latency, TTL, hostname, and cautious OS hints.
- `port_scanner.py`: bounded concurrent TCP service review.
- `risk_engine.py`: exposure priority calculation.
- `advisory_engine.py`: deterministic local summary and next actions.
- `inventory_store.py`: SQLite inventory, company context, scan snapshots, transition detection, audit records, and scan-run persistence.
- `report_builder.py`: Markdown and standalone HTML reports.

## Storage

SQLite is the primary operational data source:

```text
data/netwatch.db
```

The database uses:

- WAL journal mode
- Busy timeout
- UTC timestamps
- Indexes for scan and asset lookup
- Schema version 3 with company asset context and operational audit records
- Bounded change-event, observation, and audit retention
- Named Docker volumes in the default Compose deployment

The five operational tables have separate responsibilities:

- `scan_runs` records each check and its summary.
- `assets` stores current inventory state, last confirmed sighting, owner, department, location, criticality, and notes.
- `network_observations` records observed and not-observed evidence for each network scan.
- `asset_events` records meaningful transitions: new asset, returned asset, and not observed.
- `audit_log` records actor role, action, target, outcome, and a bounded operational summary.

A missing ICMP reply changes the current status to `Not observed` but does not overwrite the last confirmed sighting. This keeps historical evidence honest when firewalls or temporary network conditions affect discovery.

The older CSV history remains only for Streamlit compatibility.

## Security boundaries

NetWatch is intended for approved local environments and applies these controls:

- A valid Admin, Operator, or Viewer key required for every non-health API route
- Viewer can read/export, Operator can also scan, and Admin can also edit asset context
- API disabled until at least one valid role key is configured
- Server-side `authorized: true` confirmation for scans
- Explicit RFC1918, loopback, and link-local IPv4 allowlists
- Public and unsupported IPv6 targets rejected
- Maximum 256 hosts per CIDR scan
- Rate limiting per client and endpoint
- Bounded simultaneous scans
- Restricted CORS origins
- Content Security Policy and defensive HTTP headers
- API responses marked `no-store`
- Non-root Docker user
- Localhost-only published port by default
- No exploitation, brute force, credential testing, stealth, or evasion features

## Deployment model

The default Docker Compose service is intentionally single-process and local-only:

```text
127.0.0.1:8000 -> FastAPI + dashboard + API
```

This keeps setup simple and avoids cross-origin configuration. Role keys provide coarse separation for a trusted internal pilot, not individual identity. For shared or remote deployment, add a reviewed reverse proxy, TLS, organization authentication, network restrictions, centralized logging, backups, and stronger operational monitoring.
