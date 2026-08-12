# Security Policy

## Intended use

NetWatch is intended for authorized local-network visibility, defensive administration, cybersecurity education, and controlled lab use.

It is not an Internet scanner and it does not include exploitation, credential testing, brute force, stealth, evasion, or persistence features.

## Built-in safeguards

NetWatch v1.7 includes:

- Verified OIDC bearer identity or valid Admin, Operator, or Viewer key required for every non-health API endpoint
- Strict issuer, audience, asymmetric algorithm, signing key, expiry, subject, authorized-party, and exact group-to-role validation
- Invalid bearer tokens never fall back to a simultaneously supplied local key
- Malformed or ambiguous authorization headers are rejected, and local role-key values must be unique
- Viewer read/export, Operator scan/metadata-capture/alert triage, and Admin asset-context/policy/backup authorization enforced server-side
- Protected operations disabled until at least one non-placeholder role key of 32+ characters is configured
- Constant-time API-key comparison
- Server-side authorization confirmation for scan and traffic-metadata requests
- Explicit local IPv4 allowlists
- Public and unsupported IPv6 targets rejected
- Maximum 256 hosts per CIDR scan
- Per-identity, route-template request rate limiting with bounded in-memory identity buckets
- Bounded simultaneous scans
- Exact capture-interface allowlisting, one concurrent capture by default, and hard 15-second/1,000-matching-frame limits
- Ethernet/IP/ARP/TCP/UDP/ICMP header parsing that immediately discards payload bytes and persists only aggregate no-payload audit evidence
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
- Linux capabilities dropped except the minimum raw-network capability required for ping and bounded packet-header capture
- FastAPI interactive documentation disabled by default
- Deterministic local Risk Advisor with no external service calls
- Optional server-side intelligence that excludes private identifiers and free-text evidence before provider calls
- Strict structured provider output with `store: false`, no model tools, no arbitrary prompts, and human review required
- Separate provider rate/concurrency limits, daily request budget, bounded timeout/output/cache, and safe local fallback
- Admin-only individual actor and request correlation in bounded audit records that never store raw role keys or bearer tokens
- Separate-key HMAC audit chain with a keyed head checkpoint, a five-second maximum public readiness cache, fresh privileged-operation fail-closed verification, and explicit legacy-row labeling
- Public liveness/readiness separation, generated response request IDs, and low-cardinality HTTP metrics/log correlation
- Admin-approved private CIDR scan policies with bounded count and intervals
- Opt-in single-process scheduler that shares the normal scan concurrency limit
- Deduplicated criticality-aware alert cases with bounded retention, occurrence evidence, assignment, local SLA due times, acknowledgement, and evidence-backed resolution
- Bounded timezone-aware maintenance windows that pause applicable scheduled and manual policy execution
- Authenticated monitoring counters without target, IP, hostname, or other high-cardinality labels
- Admin-only consistent SQLite snapshot downloads and no destructive restore endpoint

## Secrets

The `.env` file can contain local role keys, the separate audit HMAC key, optional `OPENAI_API_KEY`, and automatically generated AI safety identity; it is ignored by Git and excluded from Docker build context.

Do not:

- Commit `.env`
- Paste role or provider keys into issues, screenshots, reports, or chat messages
- Reuse a sensitive account password as a NetWatch role key
- Publish role keys in frontend source code
- Put `NETWATCH_AUDIT_HMAC_KEY`, `OPENAI_API_KEY`, `NETWATCH_AI_SAFETY_SECRET`, or `NETWATCH_AI_SUBJECT_ID` in JavaScript, API responses, Dockerfiles, reports, logs, or tracked production configuration

Generate a new key with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Use a different random value for each enabled role and restart NetWatch after changing keys. `scripts/start.py` also creates a separate random AI safety secret and opaque subject automatically; it never prints either value.

End users call the protected NetWatch intelligence endpoint and never receive the provider key or safety identity. For shared production deployment, inject the provider key and AI safety secret from managed secret storage and configure project-level spend/rate limits. Rotate a secret immediately if it is ever committed, logged, displayed, or copied outside the approved secret store.

Wildcard-only Host or CORS allowlists are ignored. Keep the explicit localhost defaults unless a reviewed deployment requires additional names or origins.

## Notifications

Outbound alert delivery is disabled until `NETWATCH_WEBHOOK_URL` or `NETWATCH_SLACK_WEBHOOK_URL` is explicitly configured. Every configured endpoint must use HTTPS and cannot contain embedded credentials, a query string, or a fragment. NetWatch does not follow redirects, uses bounded five-second requests and response reads, limits retry attempts with exponential backoff, and opens a circuit breaker after repeated delivery failures.

Notification payloads are de-identified by default and contain only an alert reference, severity, status, category, occurrence count, and SLA state. Raw targets are excluded unless an administrator explicitly sets `NETWATCH_NOTIFY_INCLUDE_RAW_TARGETS=true`. Free-text evidence, owners, assignment details, and resolution notes are never included in outbound payloads.

Webhook URLs, including secret-bearing Slack paths, are never logged or returned by the API. The Admin-only notification status endpoint exposes only each channel kind and whether it is safely enabled. Store webhook URLs in managed secret storage, rotate them after suspected exposure, and keep the default 15-minute debounce unless a reviewed operational need requires a bounded change.

## Local data

NetWatch stores operational information in SQLite and may create logs or exported reports. These can contain private IP addresses, hostnames, MAC/manufacturer/device-identity evidence, service exposure, and internal network structure. Traffic capture metadata is returned to the authorized browser session rather than written to SQLite, but remains sensitive internal evidence.

Default SQLite path:

```text
data/netwatch.db
```

Docker Compose stores data in named volumes. Keep database files, volume exports, downloaded snapshots, screenshots, and reports inside the authorized environment.

## Deployment limits

The default deployment is designed for a trusted local pilot or small internal team and binds to:

```text
127.0.0.1:8000
```

Before shared, remote, or public deployment, add and review:

- TLS
- An approved OIDC-aware gateway that forwards signed bearer tokens
- Least-privilege dedicated IdP groups and controlled break-glass access
- Network access controls
- Managed secret storage
- Centralized append-only export of the locally integrity-protected audit stream
- External scheduler/worker coordination for multi-instance deployments
- Centralized monitoring and alert delivery
- Automated encrypted off-host backups, restore drills, and database migrations
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
