# NetWatch

![NetWatch Banner](a_high_tech_dark_ui_marketing_banner_dashboard_p_1.png)

NetWatch is a local network visibility and defensive review project built with Python. It provides a Streamlit dashboard, a protected FastAPI backend, a static frontend foundation, SQLite inventory, local risk guidance, and report exports.

It is designed for networks you own or are explicitly authorized to assess. It is not an Internet scanner and it does not replace a professional security audit.

## Current release: v0.7.1

This release focuses on security and deployment hardening:

- Mandatory API key for every non-health API endpoint
- Restricted CORS allowlist instead of wildcard browser access
- Server-side authorization confirmation for scan requests
- Rate limiting and bounded concurrent scans
- API scanning disabled until a key is configured
- FastAPI documentation disabled by default
- Explicit local IPv4 scope with clear IPv6 rejection
- Saved findings included in API reports and Risk Advisor output
- SQLite WAL mode, busy timeout, UTC timestamps, and indexes
- Non-root Docker execution and loopback-only published ports
- API security tests and GitHub Actions CI

## Architecture

```text
Browser / Streamlit
        |
        v
Protected FastAPI API
        |
        v
Validation -> Discovery / Port Audit -> Risk Advisor
        |
        v
SQLite inventory and reports
```

NetWatch currently contains two user-interface paths:

- `app.py`: complete Streamlit dashboard
- `frontend/`: static frontend foundation that communicates with `backend/main.py`

The FastAPI backend and frontend are kept separate so the project can evolve toward a standard frontend/API architecture without removing the working Streamlit demo.

## Main features

- Check one approved local IPv4 address
- Scan a conservative local IPv4 CIDR range
- Review a short list of common TCP services
- Display latency, TTL, hostname, response time, and device-role hints
- Save assets and last-seen information in SQLite
- Calculate an exposure priority score
- Generate local Risk Advisor notes
- Export CSV, Markdown, and HTML reports
- Keep a local history of completed checks
- Block public targets, oversized ranges, and unsupported IPv6 targets

## Security model

NetWatch applies defense in depth:

- Only explicit local IPv4 ranges are accepted
- CIDR scans are limited to 256 hosts
- Streamlit requires a permission checkbox
- API scans require `authorized: true` in addition to a valid API key
- API access uses the `X-NetWatch-Key` header
- API requests are rate limited
- Only one scan runs at a time by default
- Browser origins are restricted through `NETWATCH_ALLOWED_ORIGINS`
- FastAPI `/docs`, `/redoc`, and OpenAPI output are disabled by default
- CSV exports reduce spreadsheet formula-injection risk
- Custom Streamlit HTML values are sanitized
- HTML report cells are escaped
- Docker containers run as a non-root user
- Docker ports are published on `127.0.0.1` by default

The API health endpoint remains public and reports whether scanning is enabled. All inventory, history, scan, advisor, and report endpoints require authentication.

## Quick start: Streamlit

```bash
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
python -m venv venv
```

Linux/macOS:

```bash
source venv/bin/activate
```

Windows:

```powershell
venv\Scripts\activate
```

Install and run:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL shown by Streamlit, normally `http://127.0.0.1:8501`.

## Secure Docker Compose deployment

Create your environment file:

```bash
cp .env.example .env
```

Generate a strong local API key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Place the generated value in `.env` as `NETWATCH_API_KEY`, then start both services:

```bash
docker compose up -d --build
```

Local endpoints:

- Streamlit: `http://127.0.0.1:8501`
- FastAPI: `http://127.0.0.1:8000`
- Health: `http://127.0.0.1:8000/api/health`

The API starts without a key, but protected operations return HTTP `503` until `NETWATCH_API_KEY` is configured.

## API examples

Health check:

```bash
curl http://127.0.0.1:8000/api/health
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

Never commit your real `.env` file or API key.

## Run the API without Docker

Linux/macOS:

```bash
export NETWATCH_API_KEY="replace-with-a-long-random-secret"
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

PowerShell:

```powershell
$env:NETWATCH_API_KEY="replace-with-a-long-random-secret"
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Interactive API documentation is disabled by default. For local development only:

```bash
export NETWATCH_API_DOCS=true
```

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `NETWATCH_API_KEY` | empty | Enables authenticated API operations |
| `NETWATCH_ALLOWED_ORIGINS` | local port 3000 origins | Browser CORS allowlist |
| `NETWATCH_API_DOCS` | `false` | Enables FastAPI docs locally |
| `NETWATCH_MAX_CONCURRENT_SCANS` | `1` | Maximum simultaneous scans |
| `NETWATCH_RATE_LIMIT_REQUESTS` | `10` | Requests allowed per window and endpoint |
| `NETWATCH_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window |
| `NETWATCH_DATA_DIR` | `data` | SQLite data directory |

## Accuracy notes

NetWatch provides local visibility, not absolute truth:

- ICMP discovery can miss active hosts that block ping
- Reverse DNS may not return a hostname
- TTL-based operating-system hints are approximate
- An open port is an exposure requiring review, not proof of a vulnerability
- Firewalls can make services appear closed or filtered
- Device roles are inferred from observed ports and are not confirmed identification
- The configured port list is intentionally short and defensive
- IPv6 scanning is intentionally rejected until it is implemented correctly

## Data storage

SQLite is the primary inventory store:

```text
data/netwatch.db
```

The database uses WAL mode and a busy timeout to improve reliability when the Streamlit and API services access it. Saved open-port findings are reused by API reports and the Risk Advisor.

Legacy Streamlit CSV history remains available for compatibility and export workflows.

## Tests and CI

Run locally:

```bash
pytest -q
```

The GitHub Actions security workflow performs:

- Dependency installation and `pip check`
- Python source compilation
- Full pytest execution
- API authentication and CORS tests
- IPv4 scope and IPv6 rejection tests

Network calls are mocked in API tests so CI does not scan external systems.

## Project structure

```text
NetWatch/
├── app.py
├── advisory_engine.py
├── config.py
├── export_utils.py
├── history_store.py
├── host_profiler.py
├── inventory_store.py
├── logger.py
├── network_scanner.py
├── network_tools.py
├── ping_checker.py
├── port_scanner.py
├── report_builder.py
├── risk_engine.py
├── safe_text.py
├── security.py
├── service_catalog.py
├── backend/
│   ├── __init__.py
│   └── main.py
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── tests/
│   ├── test_api.py
│   ├── test_advisory_engine.py
│   ├── test_export_utils.py
│   ├── test_host_profiler.py
│   ├── test_network_tools.py
│   ├── test_report_builder.py
│   ├── test_risk_engine.py
│   ├── test_safe_text.py
│   ├── test_service_catalog.py
│   └── test_security.py
├── docs/
├── .env.example
├── .dockerignore
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## Documentation

Additional review and handover material is available in `docs/`:

- Architecture
- Deployment
- Security review
- Security hardening
- Acceptance checklist
- Company handover
- Demo script
- Kali setup
- Advisory engine notes

## Roadmap

- Normalize per-scan host and port findings into dedicated database tables
- Add scan IDs and report generation for a selected historical run
- Add ARP-based discovery where permissions allow
- Add progress reporting and scan cancellation
- Complete the static frontend and serve it through a local reverse proxy
- Add optional local user authentication for shared deployments
- Add editable asset owner, location, and business context
- Add PDF report generation

## Disclaimer

Use NetWatch only on networks and devices you own or where you have explicit authorization. Keep the API bound to localhost unless you have added proper network controls, authentication, TLS, and deployment review.
