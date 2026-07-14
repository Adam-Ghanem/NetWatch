# Security Policy

## Intended use

NetWatch is intended for authorized local-network visibility, defensive administration, cybersecurity education, and controlled lab use.

It is not an Internet scanner and it does not include exploitation, credential testing, brute force, stealth, evasion, or persistence features.

## Built-in safeguards

NetWatch v1.2 includes:

- Valid Admin, Operator, or Viewer key required for every non-health API endpoint
- Viewer read/export, Operator scan, and Admin asset-context authorization enforced server-side
- Protected operations disabled until at least one non-placeholder role key of 32+ characters is configured
- Constant-time API-key comparison
- Server-side authorization confirmation for scan requests
- Explicit local IPv4 allowlists
- Public and unsupported IPv6 targets rejected
- Maximum 256 hosts per CIDR scan
- Request rate limiting
- Bounded simultaneous scans
- Bounded common-port worker count
- Restricted CORS origins
- Restricted HTTP Host headers
- Content Security Policy
- Frame embedding blocked
- MIME sniffing disabled
- API responses marked `no-store`
- Dashboard API key stored only in browser session storage
- Dynamic custom-HTML values sanitized in the legacy interface
- CSV exports sanitized to reduce spreadsheet formula-injection risk
- HTML report values escaped
- Docker container runs as a non-root user
- Docker service published on localhost only by default
- Linux capabilities dropped except the minimum raw-network capability required for ping
- FastAPI interactive documentation disabled by default
- Local Risk Advisor with no external service calls
- Bounded operations audit records that never store raw role keys

## Secrets

The `.env` file contains the local role keys and is ignored by Git.

Do not:

- Commit `.env`
- Paste role keys into issues, screenshots, reports, or chat messages
- Reuse a sensitive account password as a NetWatch role key
- Publish role keys in frontend source code

Generate a new key with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Use a different random value for each enabled role and restart NetWatch after changing keys.

Wildcard-only Host or CORS allowlists are ignored. Keep the explicit localhost defaults unless a reviewed deployment requires additional names or origins.

## Local data

NetWatch stores operational information in SQLite and may create logs or exported reports. These can contain private IP addresses, hostnames, service exposure, and internal network structure.

Default SQLite path:

```text
data/netwatch.db
```

Docker Compose stores data in named volumes. Keep database files, volume exports, screenshots, and reports inside the authorized environment.

## Deployment limits

The default deployment is designed for a trusted local pilot or small internal team and binds to:

```text
127.0.0.1:8000
```

Before shared, remote, or public deployment, add and review:

- TLS
- SSO/OIDC organization authentication with individual identities
- Fine-grained authorization beyond shared role secrets
- Network access controls
- Managed secret storage
- Centralized tamper-resistant audit logs
- Monitoring and alerting
- Backups and database migrations
- Retention and deletion policies
- Reverse-proxy security configuration

Do not expose the default Compose service directly to the Internet.

## Reporting a vulnerability

Do not publish sensitive vulnerability details, API keys, private network maps, database contents, or internal screenshots in a public issue.

For a non-sensitive bug, include:

- A clear description
- Affected version
- Steps to reproduce
- Expected and actual behavior
- Relevant sanitized logs
- Suggested fix when available

For a sensitive security issue, use GitHub private vulnerability reporting when enabled for the repository. If it is unavailable, contact the repository owner privately before publishing technical details.
