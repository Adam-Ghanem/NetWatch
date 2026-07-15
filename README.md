<p align="center">
  <img src="frontend/assets/netwatch-logo.svg" alt="NetWatch" width="270" />
</p>

<h1 align="center">NetWatch</h1>

<p align="center">
  Local-first network visibility and defensive review for authorized environments.
</p>

<p align="center">
  <a href="https://github.com/Adam-Ghanem/NetWatch/actions/workflows/python-ci.yml"><img alt="Python CI" src="https://github.com/Adam-Ghanem/NetWatch/actions/workflows/python-ci.yml/badge.svg" /></a>
  <a href="https://github.com/Adam-Ghanem/NetWatch/actions/workflows/security-ci.yml"><img alt="Security CI" src="https://github.com/Adam-Ghanem/NetWatch/actions/workflows/security-ci.yml/badge.svg" /></a>
  <a href="https://codecov.io/gh/Adam-Ghanem/NetWatch"><img alt="Coverage" src="https://codecov.io/gh/Adam-Ghanem/NetWatch/graph/badge.svg" /></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" />
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/License-MIT-2c0f50.svg" /></a>
</p>

NetWatch is a Python, FastAPI, SQLite, and browser-based dashboard for local network visibility. It helps authorized teams discover local hosts, track what changed between scans, profile devices, review common TCP services, assign asset ownership and business criticality, schedule pre-approved private ranges, pause work during maintenance, manage deduplicated alert cases against local SLAs, export bounded monitoring metrics, create consistent backups, generate evidence-backed reports, and request optional server-side intelligence briefs from de-identified operational evidence.

> Use NetWatch only on networks and devices you own or are explicitly authorized to assess.

## Product preview

The previews below use sample data and do not contain real network identifiers.

### Overview

![NetWatch overview dashboard](docs/screenshots/overview.svg)

<table>
  <tr>
    <td width="50%"><img src="docs/screenshots/port-audit.svg" alt="NetWatch port audit preview" /></td>
    <td width="50%"><img src="docs/screenshots/risk-advisor.svg" alt="NetWatch risk advisor preview" /></td>
  </tr>
  <tr>
    <td align="center"><strong>Port audit</strong></td>
    <td align="center"><strong>Risk advisor</strong></td>
  </tr>
</table>

Capture guidance for future screenshots and short demos is documented in [`docs/screenshots/README.md`](docs/screenshots/README.md).

## NetWatch v1.6 Enterprise foundations

The default product is a responsive light corporate dashboard served together with the protected FastAPI API at one local address:

```text
http://127.0.0.1:8000
```

The original Streamlit interface remains available as an optional legacy profile, but it is no longer the default product UI.

v1.6 adds an optional enterprise identity boundary. A reviewed OIDC-aware reverse proxy can forward signed bearer tokens, which NetWatch validates against one configured HTTPS JWKS endpoint with an explicit issuer, audience, algorithm allowlist, expiry, subject, and exact company-group mapping. Users then authenticate through company SSO without receiving a NetWatch role key or provider key. Local role keys remain available for local and controlled break-glass use.

Every protected audit event can now carry an individual actor, authentication method, and request ID inside a separate-key HMAC chain with a keyed head checkpoint. Fresh full retained-chain verification gates every privileged operation; the public readiness probe reuses a result for at most five seconds to bound its cost. NetWatch also exposes separate liveness/readiness probes, low-cardinality HTTP metrics, safe correlation logs, and stricter browser headers. See the [enterprise deployment guide](docs/enterprise-deployment.md) and [Kubernetes template](deploy/kubernetes.yaml).

These controls make NetWatch suitable for a reviewed internal deployment foundation; they do not turn the current SQLite and in-process scheduler design into multi-replica HA. Large deployments still need the external controls and scale-out work listed in the enterprise guide.

## Highlights

- Responsive light corporate dashboard
- User-provided NetWatch identity and local SVG assets
- Automatic company SSO session detection plus session-only local role-key fallback
- Strict OIDC/JWT verification with exact group-to-role mapping
- Admin, Operator, and Viewer access tiers with server-side authorization
- Authorized local IPv4 CIDR discovery
- Historical scan snapshots with new, returned, and not-observed asset detection
- Single-host latency, TTL, hostname, and cautious OS hints
- Bounded concurrent common-port audit
- Clear Open, Closed, and Filtered/Unreachable states
- SQLite asset inventory with owner, department, location, criticality, and operational notes
- Admin-only individual audit identities and request correlation
- Separate-key HMAC audit chain, keyed head checkpoint, and privileged-operation fail-closed behavior
- Approved scan policies with immutable private CIDR scope and 15-minute minimum intervals
- Opt-in single-process scheduler using the existing scan concurrency limit
- Deduplicated operational alert cases for new, returned, and not-observed assets
- Criticality-aware severity, local SLA due times, assignment, acknowledgement, and evidence-backed resolution
- Bounded global or policy-specific maintenance windows that pause policy execution
- Authenticated Prometheus text-format operational and HTTP counters without target labels
- Separate public liveness and readiness endpoints
- Admin-only consistent SQLite backup download
- Exposure priority score and deterministic local Risk Advisor
- Optional server-side NetWatch Intelligence with structured defensive output
- De-identified AI snapshots that exclude private identifiers and free-text evidence
- AI cache, separate rate/concurrency limits, atomic daily request budget, redirect refusal, safe failure handling, and local fallback
- Markdown and standalone HTML report downloads
- Formula-safe inventory CSV export
- Public, oversized, and unsupported targets blocked
- API authentication, bounded per-identity rate-limit state, scan concurrency limits, and security headers
- Minimum-length API secrets and explicit HTTP Host/CORS allowlists
- Non-root Docker container with localhost-only publishing
- One-command secure launcher
- Automated Python, frontend, API, Compose, Docker, and coverage validation

## Start NetWatch

### Requirements

- Git
- Python 3.10+
- Docker Desktop or Docker Engine with Docker Compose

### Clone and launch

```bash
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
python scripts/start.py
```

The launcher automatically:

1. Creates a local `.env` file.
2. Generates a strong random Admin key.
3. Generates a separate audit HMAC key without printing it.
4. Generates an independent AI safety secret and opaque deployment subject without printing them.
5. Builds the NetWatch container.
6. Starts it on `127.0.0.1:8000`.
7. Prints the dashboard URL without exposing any credential in terminal history.

Open the displayed URL and enter the displayed key. The browser stores the key only in session storage, so closing the tab clears it.

The launcher leaves the optional Operator and Viewer keys blank. Configure them in `.env` only when separate team access is needed, and use a different 32+ character random secret for every enabled role.

## Manual Docker deployment

Create the environment file and let the launcher replace all local placeholders with independent random values. The launcher does not print secrets; the local break-glass Admin key stays in the private `.env` file:

```bash
cp .env.example .env
python -c "from scripts.start import ensure_configuration; print(ensure_configuration())"
```

For optional Intelligence, the deployment owner then supplies only the provider credential in the server-side `.env`; dashboard users never enter it:

```text
NETWATCH_OPERATOR_KEY=
NETWATCH_VIEWER_KEY=
NETWATCH_SCHEDULER_ENABLED=false
OPENAI_API_KEY=your-provider-project-key
```

Start NetWatch:

```bash
docker compose up -d --build netwatch
```

Useful commands:

```bash
docker compose ps
docker compose logs -f netwatch
docker compose restart netwatch
docker compose down
```

## Main workflows

### Overview

Shows saved assets, open services, assets requiring review, recent checks, recent asset changes, and a compact advisor summary.

### Network scan

Checks an approved local IPv4 CIDR with a maximum of 256 hosts. Each completed scan saves a normalized snapshot and compares it with earlier observations. NetWatch highlights newly observed devices, devices seen again after an absence, and known devices that did not reply this time.

ICMP filtering may hide active devices, so NetWatch uses **Not observed** instead of claiming that a missing device is offline. A zero-host result does not prove that the network is empty.

### Host check

Profiles one approved IPv4 host and displays:

- Reachability
- Round-trip latency
- TTL
- Reverse-DNS hostname
- Cautious operating-system hint
- Observation notes

### Port audit

Reviews a short defensive list of common TCP services and displays:

- Open, Closed, or Filtered/Unreachable state
- Response time
- Service description
- Exposure priority
- Review recommendation
- Device-role hint

An open port is exposure that requires context and validation. It is not automatic proof of a vulnerability.

### Inventory and history

Stores local assets, first and last confirmed sightings, status, open-service findings, exposure score, recent scan runs, normalized observations, and change events in SQLite. Admins can assign an owner, department, location, business criticality, and operational notes. Viewer and Operator roles can read this context but cannot edit it.

Inventory can be exported as formula-safe CSV for an approved internal workflow.

### Operations audit log

Records successful network scans, host checks, port audits, and controlled operations with UTC time, individual actor, role, authentication method, request ID, target, outcome, and a short summary. A separate server-only key protects new records with a chained HMAC and keyed latest-event checkpoint; full retained-chain verification pauses privileged operations after detected tampering. Raw API keys and bearer tokens are never written to the log. Retention is bounded to the latest 10,000 events, and pre-v1.6 rows remain clearly marked as legacy rather than being silently re-signed.

### Company operations

The Operations view supports five controlled workflows:

- Admins save one policy per approved private CIDR, choose a bounded interval from 15 minutes to 7 days, and enable or disable scheduled execution.
- Operators and Admins can run a saved policy after confirming current authorization. The same target validation, 256-host limit, rate boundary, and scan semaphore apply.
- Admins can document a bounded global or policy-specific maintenance window. Active windows pause both scheduled and manual policy runs.
- Viewer roles can review policies, cases, SLA state, and maintenance windows. Operators and Admins can assign, acknowledge, resolve with evidence, or reopen cases.
- Authenticated users can export bounded monitoring counters without private IP or target labels. Admins can download a consistent SQLite snapshot.

Scheduled execution is disabled by default. Enable it explicitly with `NETWATCH_SCHEDULER_ENABLED=true` after the approved policies and operating procedure have been reviewed. The scheduler runs inside the single FastAPI process and is not intended for multi-worker or multi-instance deployment.

### Risk Advisor

Builds a deterministic local summary from saved evidence. It does not send scan data outside the local machine.

### NetWatch Intelligence

Provides an optional second review through the server-side OpenAI Responses API. End users never enter or receive the provider key. NetWatch sends only a bounded, de-identified JSON snapshot, requests strict structured output with storage disabled, and requires human validation before action. It does not accept arbitrary prompts, expose model tools, choose targets, run scans, change cases, or execute recommendations.

Repeated requests for the same evidence use a local cache. Separate request-rate and concurrency controls plus an atomic day-keyed provider-call counter protect availability and cost even under concurrent cache misses. Provider redirects are rejected so the bearer credential is never forwarded to another location. Platform project spend limits remain a deployment-owner control outside NetWatch.

### Reports

Downloads:

- Markdown report for GitHub, notes, or handover documents
- Standalone HTML report for review and sharing inside an authorized environment

Both formats include asset business context, recent changes, alert case/SLA evidence, approved scan policies, maintenance windows, operations audit events, inventory, and port evidence.

## Architecture

```text
Responsive dashboard (`frontend/`)
              |
              v
Role-protected FastAPI application (`backend/main.py`)
              |
    +---------+----------+
    |         |          |
Validation  Scanners   Operations
    |         |          |
    +---------+----------+
              |
              v
       SQLite + reports
              |
              +--> Optional de-identification gate --> OpenAI Responses API
```

The FastAPI process serves both the dashboard and the `/api/*` endpoints. This same-origin design avoids unnecessary cross-origin complexity and gives the project one clear production-style entry point.

## Security model

NetWatch applies defense in depth:

- A verified company bearer token or `X-NetWatch-Key` is required for all non-health API endpoints
- Exact OIDC issuer, audience, asymmetric algorithm, signing key, expiry, subject, authorized-party, and group validation
- Admin (`NETWATCH_API_KEY`), optional Operator, and optional Viewer keys remain available for local/break-glass use
- Viewer can read and export; Operator can also run authorized checks and triage alert cases; Admin can also edit asset context, manage approved policies and maintenance windows, and create backups
- Protected access disabled until a valid OIDC mapping or at least one unique valid role key is configured
- Server-side `authorized: true` required for scan requests
- Explicit local IPv4 allowlists
- Public and unsupported IPv6 targets rejected
- CIDR scans limited to 256 hosts
- Rate limiting per authenticated identity and endpoint
- Invalid bearer tokens never fall back to a simultaneously supplied shared key
- Admin-only individual audit identity plus separate-key retained HMAC-chain verification
- Generated response request IDs, safe route-template correlation logs, and separate liveness/readiness probes
- One simultaneous scan by default
- Scheduled scans are opt-in, use persisted Admin-approved private CIDRs, and share the same scan semaphore
- Policy intervals are limited to 15 minutes through 7 days and policy count is bounded to 50
- Maintenance windows are timezone-aware, limited to 31 days, bounded to 100 records, and enforced before policy execution
- Unresolved alert repeats are deduplicated; closure requires resolution evidence
- Authenticated metrics expose only bounded numeric counters and never target labels
- `OPENAI_API_KEY` is read only by the backend and excluded from Git, Docker images, browser code, logs, reports, API responses, and stored intelligence records
- The launcher creates a distinct `NETWATCH_AI_SAFETY_SECRET` and opaque `NETWATCH_AI_SUBJECT_ID`; neither is sent to the provider, browser, logs, or SQLite
- Intelligence input contains bounded aggregates rather than IPs, CIDRs, hostnames, ownership fields, locations, notes, or raw event details
- Intelligence calls use strict structured output, `store: false`, a key-separated opaque safety identifier, no model tools, redirect refusal, separate rate/concurrency limits, an atomic daily budget independent of cache retention, and bounded cache retention
- Dashboard API requests are restricted to the page's own origin; URL query parameters cannot redirect role credentials to another API
- Provider failure cannot disable the deterministic local advisor or core monitoring workflows
- Restricted CORS origins
- Content Security Policy
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- API responses marked `no-store`
- CSV and HTML export sanitization
- Non-root Docker user
- Docker port published only on `127.0.0.1`
- No exploitation, brute force, credential testing, stealth, persistence, or evasion functionality

The liveness, readiness, and summary health endpoints are public so orchestration can assess service state without credentials. All operational endpoints require authentication. OIDC provides individual identity when a reviewed gateway forwards the signed token; local role keys identify a shared role and should be limited to local or break-glass use.

## API examples

Health:

```bash
curl http://127.0.0.1:8000/api/health
```

Current role and capabilities:

```bash
curl http://127.0.0.1:8000/api/session \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY"
```

Authorized network scan:

```bash
curl -X POST http://127.0.0.1:8000/api/scan/network \
  -H "Content-Type: application/json" \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY" \
  -d '{"cidr":"192.168.1.0/24","authorized":true}'
```

Authorized port audit:

```bash
curl -X POST http://127.0.0.1:8000/api/audit/ports \
  -H "Content-Type: application/json" \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY" \
  -d '{"ip":"192.168.1.1","authorized":true}'
```

Recent asset changes:

```bash
curl http://127.0.0.1:8000/api/changes \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY"
```

Normalized network observations:

```bash
curl "http://127.0.0.1:8000/api/observations?limit=100" \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY"
```

Update company context for a saved asset (Admin only):

```bash
curl -X PATCH http://127.0.0.1:8000/api/assets/192.168.1.20 \
  -H "Content-Type: application/json" \
  -H "X-NetWatch-Key: YOUR_ADMIN_KEY" \
  -d '{"owner":"Platform Team","department":"IT","location":"HQ","criticality":"Critical","notes":"Core internal service"}'
```

Review recent operational events:

```bash
curl "http://127.0.0.1:8000/api/audit-log?limit=100" \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY"
```

Create an approved scan policy (Admin only):

```bash
curl -X POST http://127.0.0.1:8000/api/scan-policies \
  -H "Content-Type: application/json" \
  -H "X-NetWatch-Key: YOUR_ADMIN_KEY" \
  -d '{"name":"HQ baseline","cidr":"192.168.1.0/24","interval_minutes":60,"enabled":false,"authorized":true}'
```

Review open operational alerts:

```bash
curl "http://127.0.0.1:8000/api/alerts?status=open" \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY"
```

Create a policy-specific maintenance window (Admin only):

```bash
curl -X POST http://127.0.0.1:8000/api/maintenance-windows \
  -H "Content-Type: application/json" \
  -H "X-NetWatch-Key: YOUR_ADMIN_KEY" \
  -d '{"name":"HQ firewall change","starts_at":"2026-07-15T20:00:00+00:00","ends_at":"2026-07-15T22:00:00+00:00","reason":"CHG-1042","policy_id":1,"enabled":true}'
```

Export authenticated operational metrics:

```bash
curl http://127.0.0.1:8000/api/metrics \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY" \
  -o netwatch-metrics.prom
```

Check optional intelligence availability:

```bash
curl http://127.0.0.1:8000/api/intelligence/status \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY"
```

Generate or reuse a de-identified intelligence brief:

```bash
curl -X POST http://127.0.0.1:8000/api/intelligence/brief \
  -H "Content-Type: application/json" \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY" \
  -d '{"refresh":false}'
```

Download a consistent database snapshot (Admin only):

```bash
curl http://127.0.0.1:8000/api/backups/database \
  -H "X-NetWatch-Key: YOUR_ADMIN_KEY" \
  -o netwatch-backup.sqlite3
```

Export the inventory:

```bash
curl http://127.0.0.1:8000/api/inventory/export.csv \
  -H "X-NetWatch-Key: YOUR_LOCAL_KEY" \
  -o netwatch-inventory.csv
```

## Local development

Create a virtual environment and install development dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
pre-commit install
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Run the application:

Linux/macOS:

```bash
export NETWATCH_API_KEY="development-only-secret-at-least-32-chars"
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Windows PowerShell:

```powershell
$env:NETWATCH_API_KEY="development-only-secret-at-least-32-chars"
uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

The original Streamlit UI is optional:

```bash
docker compose --profile legacy up -d streamlit
```

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `NETWATCH_API_KEY` | empty | Admin key; 32+ characters; read, scan, and asset-context access |
| `NETWATCH_OPERATOR_KEY` | empty | Optional Operator key; read and authorized scan access |
| `NETWATCH_VIEWER_KEY` | empty | Optional Viewer key; read and export access only |
| `NETWATCH_AUDIT_HMAC_KEY` | generated by launcher | Independent server-only key for protected audit links and the head checkpoint |
| `NETWATCH_OIDC_ENABLED` | `false` | Enables fail-closed company bearer-token verification |
| `NETWATCH_OIDC_ISSUER` | empty | Exact HTTPS issuer |
| `NETWATCH_OIDC_AUDIENCE` | empty | Exact NetWatch audience/client identifier |
| `NETWATCH_OIDC_JWKS_URL` | empty | Deployment-controlled HTTPS signing-key endpoint |
| `NETWATCH_OIDC_GROUPS_CLAIM` | `groups` | Bounded token claim containing the company groups list |
| `NETWATCH_OIDC_ADMIN_GROUPS` | empty | Exact comma-separated groups mapped to Admin |
| `NETWATCH_OIDC_OPERATOR_GROUPS` | empty | Exact comma-separated groups mapped to Operator |
| `NETWATCH_OIDC_VIEWER_GROUPS` | empty | Exact comma-separated groups mapped to Viewer |
| `NETWATCH_OIDC_ALGORITHMS` | `RS256` | Explicit asymmetric signing-algorithm allowlist |
| `NETWATCH_OIDC_CLOCK_SKEW_SECONDS` | `30` | Bounded identity-provider clock tolerance |
| `NETWATCH_OIDC_MAX_TOKEN_AGE_SECONDS` | `3600` | Maximum signed token lifetime, bounded from 5 minutes to 24 hours |
| `NETWATCH_OIDC_JWKS_CACHE_SECONDS` | `300` | Bounded provider signing-key-set cache lifetime |
| `NETWATCH_OIDC_JWKS_TIMEOUT_SECONDS` | `5` | Bounded HTTPS signing-key lookup timeout |
| `NETWATCH_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Accepted HTTP Host headers |
| `NETWATCH_ALLOWED_ORIGINS` | localhost port 8000 | Browser CORS allowlist |
| `NETWATCH_API_DOCS` | `false` | Enables FastAPI docs for local development |
| `NETWATCH_MAX_CONCURRENT_SCANS` | `1` | Simultaneous scan limit |
| `NETWATCH_RATE_LIMIT_REQUESTS` | `30` | Requests per endpoint/window |
| `NETWATCH_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window |
| `NETWATCH_PORT_SCAN_WORKERS` | `12` | Bounded TCP review workers |
| `NETWATCH_SCHEDULER_ENABLED` | `false` | Enables execution of due approved policies in the single API process |
| `NETWATCH_SCHEDULER_POLL_SECONDS` | `30` | Scheduler polling interval, bounded from 5 to 300 seconds |
| `OPENAI_API_KEY` | empty | Optional server-side provider secret; never send it to the browser or commit it |
| `NETWATCH_AI_SAFETY_SECRET` | generated by launcher | Independent server-only pseudonymization secret; must differ from `OPENAI_API_KEY` |
| `NETWATCH_AI_SUBJECT_ID` | generated by launcher | Opaque random deployment subject; never use a role, username, hostname, or address |
| `NETWATCH_AI_ENABLED` | `true` | Allows intelligence only when the provider key and independent safety identity are usable |
| `NETWATCH_AI_MODEL` | `gpt-5.6-luna` | Server-selected model for bounded high-volume briefs |
| `NETWATCH_AI_TIMEOUT_SECONDS` | `25` | Upstream timeout, bounded from 5 to 60 seconds |
| `NETWATCH_AI_MAX_OUTPUT_TOKENS` | `1200` | Structured response budget, bounded from 256 to 4000 tokens |
| `NETWATCH_AI_MAX_CONCURRENT_REQUESTS` | `2` | Simultaneous provider request limit |
| `NETWATCH_AI_RATE_LIMIT_REQUESTS` | `5` | Provider calls allowed per client/window |
| `NETWATCH_AI_RATE_LIMIT_WINDOW_SECONDS` | `600` | Separate provider-call rate window |
| `NETWATCH_AI_DAILY_REQUEST_LIMIT` | `50` | Application-level provider-call budget per UTC day |
| `NETWATCH_AI_CACHE_TTL_SECONDS` | `900` | Successful brief cache lifetime |
| `NETWATCH_DATA_DIR` | `data` | SQLite data directory |

## Data storage

SQLite is the main operational store:

```text
data/netwatch.db
```

The database uses WAL mode, busy timeout, UTC timestamps, and indexes. Docker Compose persists it in a named volume. Its main records are:

- `scan_runs`: one audit record per completed check
- `assets`: current inventory, last confirmed sighting, ownership, location, criticality, and notes
- `network_observations`: normalized observed/not-observed evidence per network scan
- `asset_events`: new, returned, and not-observed transitions
- `audit_log`: bounded role/action/target records for operational accountability
- `scan_policies`: Admin-approved private CIDRs, intervals, enablement, and last/next run state
- `operation_alerts`: deduplicated alert cases with severity, occurrence count, SLA, assignment, acknowledgement, and resolution evidence
- `maintenance_windows`: bounded global or policy-specific execution pauses with UTC schedule and change reason
- `intelligence_events`: bounded provider-call metadata, safe error codes, token counts, and de-identified structured brief cache; prompts, snapshots, keys, and raw network evidence are not stored

Change history is bounded to 5,000 events, 50,000 network observations, 10,000 audit records, 5,000 alerts, 50 scan policies, 100 maintenance windows, and 1,000 intelligence events so a long-running local installation does not grow without limit.

The older CSV history remains only for compatibility with the optional Streamlit interface.

## Tests, coverage, and code quality

Install the development toolchain:

```bash
make dev-install
```

Run checks locally:

```bash
make test
make coverage
make lint
make typecheck
make pre-commit
node --check frontend/app.js
docker compose config --quiet
docker build -t netwatch-local .
```

Quality configuration is centralized in:

- `pyproject.toml`
- `.flake8`
- `.pre-commit-config.yaml`
- `requirements-dev.txt`
- `codecov.yml`

GitHub Actions validates formatting, imports, lint, typing, tests, coverage, dependency vulnerabilities, Python source compilation, frontend JavaScript syntax, Docker Compose configuration, the production container build, container privilege boundaries, dashboard/static asset serving, API authentication, Host/CORS rules, security headers, and local target restrictions.

Network actions are mocked in API tests, so CI does not scan external systems.

## Accuracy limitations

NetWatch provides useful local evidence, not absolute truth:

- ICMP discovery can miss hosts that block ping
- **Not observed** means no reply in the latest relevant scan; it does not mean confirmed offline
- Reverse DNS may not return a hostname
- TTL-based OS hints are approximate
- Firewalls can affect Closed and Filtered results
- Device roles are inferred from observed services
- The port list is intentionally short
- IPv6 scanning is rejected until correctly implemented
- Important findings should be validated with the device or network owner

## Project structure

```text
NetWatch/
├── backend/
│   ├── __init__.py
│   └── main.py
├── frontend/
│   ├── assets/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── scripts/
│   ├── __init__.py
│   └── start.py
├── tests/
├── docs/
│   └── screenshots/
├── app.py                  # optional legacy Streamlit UI
├── advisory_engine.py
├── config.py
├── host_profiler.py
├── inventory_store.py
├── network_scanner.py
├── operations_store.py
├── port_scanner.py
├── report_builder.py
├── risk_engine.py
├── security.py
├── service_catalog.py
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
├── .pre-commit-config.yaml
├── .env.example
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

## Roadmap

- Per-scan normalized service findings
- Configurable retention and cleanup controls
- Local CVE enrichment with explicit version-confidence handling
- ARP discovery where operating-system permissions allow
- Progress updates and cancellation for longer scans
- PDF reports
- Safe public demo mode with sample data and scanning disabled
- PostgreSQL-backed multi-instance persistence and distributed rate/quota state
- External scheduler/worker coordination with leader election
- Encrypted off-host backup rotation, restore drills, and migration tooling

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. The project accepts defensive improvements, tests, documentation, accessibility work, performance improvements, and carefully scoped local-security features.

## License

NetWatch is released under the [MIT License](LICENSE).

## Disclaimer

NetWatch is a defensive local visibility tool. Use it only with clear authorization. v1.6 can form the application layer of a reviewed internal company deployment, but it must not be exposed directly to the Internet or treated as a multi-tenant or multi-replica HA service without the external controls and architecture described in the enterprise deployment guide.
