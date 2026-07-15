# NetWatch v1.4 Security Review

## Scope

This review covers the default local deployment of NetWatch v1.4: one FastAPI process serving the responsive dashboard, role-protected API, optional bounded scheduler, case workflow, maintenance controls, and authenticated metrics at `127.0.0.1:8000`.

## Threat model

NetWatch runs on a trusted operator machine connected to an authorized network. Relevant risks include:

- A malicious webpage attempting to call a locally running API
- An unauthorized local user accessing inventory or initiating scans
- Accidental scanning of public or oversized ranges
- Concurrent scans exhausting local resources
- Sensitive internal evidence leaking through files, reports, browser caching, or Git
- Container compromise receiving unnecessary privileges
- Dynamic scan values being interpreted as HTML or spreadsheet formulas
- A stale or over-broad scheduled policy continuing after authorization changes
- Concurrent scheduler instances running the same approved policy
- Database snapshots exposing internal inventory if mishandled
- Duplicate findings overwhelming triage or being closed without evidence
- Scheduled work continuing during a documented maintenance window
- Monitoring labels exposing private targets or producing unbounded cardinality

## Implemented controls

### API access

- All non-health endpoints require `X-NetWatch-Key`.
- Admin, Operator, and Viewer keys are compared with `hmac.compare_digest`.
- Viewer can read/export, Operator can also scan and triage alerts, and Admin can also edit asset context, manage policies, and download snapshots.
- Protected operations return HTTP 503 when no valid non-placeholder role key of at least 32 characters is configured.
- The dashboard stores the key only in session storage.

### Browser boundary

- Dashboard and API use the same origin by default.
- CORS permits only configured local origins.
- HTTP Host headers are restricted to configured local names and addresses.
- Content Security Policy restricts scripts, styles, connections, objects, frames, and forms.
- Frame embedding is denied.
- MIME sniffing is disabled.
- Referrer information is not sent.
- Camera, microphone, and geolocation permissions are disabled.
- API responses use `Cache-Control: no-store`.

### Scan safety

- Scan requests require explicit server-side authorization confirmation.
- Targets are restricted to approved local IPv4 ranges.
- Public and unsupported IPv6 targets are rejected.
- CIDR scans are limited to 256 hosts.
- API requests are rate limited per client and endpoint.
- Simultaneous scans are bounded.
- Port workers are bounded.
- Scanner timeouts, configuration values, and inventory query sizes are bounded.
- The service list is intentionally conservative.
- Scan policies are Admin-only, private-CIDR-only, limited to 50, and use intervals from 15 minutes to 7 days.
- Policy CIDRs are immutable after approval; enable/disable state and interval remain auditable controls.
- The scheduler is disabled by default, atomically claims one due policy per cycle, and shares the normal scan semaphore.
- Manual policy execution requires fresh authorization confirmation.
- Active global or policy-specific maintenance windows pause applicable scheduler claims and manual policy runs.
- Maintenance timestamps require a timezone, duration is limited to 31 days, and records are bounded to 100.

### Storage and output

- SQLite uses WAL mode and busy timeout.
- Timestamps are stored in UTC.
- Asset events, normalized observations, and operations audit records have bounded retention.
- Audit records contain role, action, target, outcome, and short details but never raw API keys.
- Existing databases migrate company-context, policy, alert, and audit records in place at schema version 5.
- Transition-derived cases have bounded retention, deduplicate unresolved repeats, calculate local SLA state, and retain assignment/acknowledgement/resolution evidence.
- A resolution note is required before a case can be closed; later recurrence creates a new open case.
- Authenticated operational metrics use fixed numeric series and do not contain target or user-provided labels.
- Not-observed severity uses business criticality but still avoids claiming confirmed downtime.
- Admin snapshots use SQLite's online backup API; no destructive restore API is exposed.
- Missing ICMP replies preserve the last confirmed sighting and use `Not observed` rather than a definitive offline claim.
- Database and generated files are ignored by Git.
- CSV output reduces spreadsheet formula injection, including leading-whitespace variants.
- HTML report values are escaped.
- Markdown table delimiters and line breaks are escaped.
- The dashboard renders dynamic values with text nodes instead of HTML insertion.

### Container controls

- The container runs as a non-root user.
- Docker Compose drops all Linux capabilities and adds only `NET_RAW` for ping.
- `no-new-privileges` is enabled.
- Port `8000` is published only on `127.0.0.1`.
- Local data is persisted in named volumes.
- The image excludes local secrets and generated data through `.dockerignore`.

## Residual risks

- A user with access to the local machine and `.env` can obtain configured role keys.
- Role keys are shared secrets, not individual user identity or non-repudiation.
- Localhost binding does not protect against every malicious process running under the same user account.
- ICMP and TCP observations can be incomplete or misleading due to filtering and transient network conditions.
- The in-memory rate limiter resets when the process restarts and is not suitable for a multi-worker deployment.
- SQLite and the current schema are designed for a trusted local pilot, not high-concurrency multi-tenant use.
- The local audit table is useful operational evidence but is not centralized or tamper-resistant.
- Change events remain network evidence and can contain sensitive internal addressing even without hostnames.
- Reports and screenshots can expose sensitive internal information if shared carelessly.
- The in-process scheduler is not safe for multi-worker or multi-instance coordination.
- Shared role keys identify a role, not the individual who approved a policy or acknowledged an alert.
- A downloaded snapshot is not an automated encrypted off-host backup or a tested disaster-recovery plan.
- Local SLA due times are workflow guidance, not an organization-wide incident-management or paging service.
- Maintenance checks depend on the single local process and shared SQLite clock evidence.

## Shared-deployment requirements

Do not expose the default service to other networks without adding:

- TLS
- SSO/OIDC organization authentication and individual identities
- Fine-grained authorization beyond shared role keys
- Managed secrets
- Network restrictions
- Centralized audit logging
- External scheduler/worker coordination with leader election
- Centralized monitoring and alert delivery
- Automated encrypted off-host backup, tested restore, and migration procedures
- Retention/deletion policy
- Dependency and container vulnerability management
- A deployment-specific penetration test and privacy review

## Review conclusion

The default NetWatch v1.4 configuration is appropriate for a trusted local pilot or small internal team when used only on authorized networks and operated according to the deployment guide. It is not approved as-is for public, multi-tenant, multi-instance, or Internet-accessible deployment.
