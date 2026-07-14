# NetWatch v1.3 Deployment Guide

NetWatch is designed to run locally on a trusted laptop, workstation, or lab VM connected to an authorized network.

## Recommended installation: one command

Requirements:

- Git
- Python 3.10 or newer
- Docker Desktop or Docker Engine with Docker Compose

Clone the repository and start NetWatch:

```bash
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
python scripts/start.py
```

The launcher:

1. Creates `.env` when necessary.
2. Generates a strong random Admin key.
3. Builds the production container.
4. Starts NetWatch on localhost.
5. Prints the URL and API key.

Open:

```text
http://127.0.0.1:8000
```

Enter the printed key in the dashboard connection screen. The browser stores it only in session storage, so closing the tab clears it.

The optional Operator and Viewer roles remain disabled until their separate keys are configured.

## Manual Docker Compose installation

Create the environment file:

```bash
cp .env.example .env
```

Generate a secure key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Place the value in `.env`:

```text
NETWATCH_API_KEY=your-generated-secret
NETWATCH_OPERATOR_KEY=
NETWATCH_VIEWER_KEY=
NETWATCH_SCHEDULER_ENABLED=false
```

Build and start:

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

## Local Python development

Create a virtual environment:

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Set an API key and run FastAPI:

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

## Optional legacy Streamlit interface

The original dashboard remains available but is not started by default:

```bash
docker compose --profile legacy up -d streamlit
```

Open:

```text
http://127.0.0.1:8501
```

## Configuration

| Environment variable | Default | Description |
|---|---:|---|
| `NETWATCH_API_KEY` | empty | Admin key: read, scan, and asset-context management |
| `NETWATCH_OPERATOR_KEY` | empty | Optional Operator key: read and authorized scans |
| `NETWATCH_VIEWER_KEY` | empty | Optional Viewer key: read and export only |
| `NETWATCH_ALLOWED_HOSTS` | `127.0.0.1,localhost` | Accepted HTTP Host headers |
| `NETWATCH_ALLOWED_ORIGINS` | localhost port 8000 | Browser CORS allowlist |
| `NETWATCH_API_DOCS` | `false` | Enables FastAPI documentation for local development |
| `NETWATCH_MAX_CONCURRENT_SCANS` | `1` | Simultaneous scan limit |
| `NETWATCH_RATE_LIMIT_REQUESTS` | `30` | Requests allowed per endpoint/window |
| `NETWATCH_RATE_LIMIT_WINDOW_SECONDS` | `60` | Rate-limit window |
| `NETWATCH_PORT_SCAN_WORKERS` | `12` | Bounded common-port worker count |
| `NETWATCH_SCHEDULER_ENABLED` | `false` | Enables due approved policies in the single API process |
| `NETWATCH_SCHEDULER_POLL_SECONDS` | `30` | Poll interval, bounded from 5 to 300 seconds |
| `NETWATCH_DATA_DIR` | `data` | Local SQLite directory |

## Persistent data

The Compose deployment uses named volumes:

```text
netwatch-data
netwatch-logs
```

Inspect them with:

```bash
docker volume ls
docker volume inspect netwatch_netwatch-data
```

Removing the Compose stack does not delete data unless `-v` is used:

```bash
docker compose down -v
```

The `-v` option permanently deletes the saved NetWatch database and logs.

Back up the named data volume before upgrades or operational use. The v1.3 database migration creates the policy and alert tables in place while preserving existing inventory. A pre-upgrade backup is still the required safe operating procedure.

Admins can also use **Operations → Download database backup** to create a consistent point-in-time SQLite snapshot. The download does not include `.env` role keys. Store it in an approved encrypted location and test restoration on a separate staging copy.

Do not overwrite a live database to restore a snapshot. Stop NetWatch, preserve the current database as a rollback copy, validate the candidate with SQLite `PRAGMA integrity_check`, restore according to the deployment owner's volume procedure, then start NetWatch and verify `/api/health`, inventory, policies, and alerts. v1.3 provides consistent snapshot creation; it does not automate destructive restore operations or off-host retention.

## Safe operating procedure

- Run NetWatch only on a trusted machine.
- Keep port `8000` bound to `127.0.0.1` unless deployment security is reviewed.
- Begin with one known host or a small CIDR such as `/28`.
- Confirm written or explicit authorization before every assessment.
- Treat open services as evidence requiring validation, not automatic vulnerabilities.
- Assign owners and criticality to important assets.
- Review the operations audit log after important checks.
- Review and acknowledge operational alerts with the system owner.
- Keep scheduled execution disabled until each policy has durable approval.
- Disable a policy immediately when its approval or scope changes.
- Download and protect a consistent snapshot before upgrades.
- Export reports after important checks.
- Do not publish `.env`, database files, internal IP maps, or exported reports.

## Trusted internal pilot

For a small team on one controlled workstation, configure a distinct key per enabled role:

| Role | Capabilities |
|---|---|
| Viewer | Dashboard, inventory, policies, alerts, audit log, reports, CSV export |
| Operator | Viewer capabilities plus authorized checks, manual policy runs, and alert triage |
| Admin | Operator capabilities plus asset context, policy management, and snapshot download |

These are shared role secrets, not individual identities. Store them in an approved secret manager where possible, rotate them when access changes, and do not send them through source control or screenshots.

## Shared or remote deployment boundary

The default deployment is intended for one trusted local pilot or small internal team. Before exposing NetWatch to remote users, public interfaces, or a multi-user production environment, add:

- TLS through a maintained reverse proxy
- Organization identity with SSO/OIDC and individual authorization
- Network-level access restrictions
- Secret management instead of `.env`
- Centralized tamper-resistant audit logging and retention rules
- Automated encrypted off-host backups, restore drills, and database migration procedures
- Health monitoring and alerting
- A deployment-specific security review
