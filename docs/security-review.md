# NetWatch v1.6 Security Review

## Scope

This review covers NetWatch v1.6: one FastAPI process serving the responsive dashboard, optional OIDC identity verification, local role-key fallback, integrity-protected audit records, probes, metrics, bounded scheduler, case workflow, deterministic local advisor, and optional server-side intelligence gateway.

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
- A public repository, browser bundle, container image, log, report, or database exposing a provider key
- Private network identifiers or free-text business context leaving NetWatch in a provider request
- Prompt injection through saved evidence, malformed model output, provider outage, or repeated calls causing unsafe actions, downtime, or cost abuse
- Forged, expired, wrong-tenant, wrong-audience, or algorithm-confused enterprise identity tokens
- Attacker-controlled JWT key references or an unavailable identity-provider JWKS endpoint
- Local audit rows being changed after a privileged operation

## Implemented controls

### API access

- All non-health endpoints require a verified company bearer token or a valid local role key.
- Company tokens require a configured HTTPS issuer/JWKS endpoint, exact issuer and audience, allowed asymmetric signature algorithm, bounded key ID, expiry, issue time, subject, authorized party when present, and exact group mapping.
- Token headers cannot redirect key lookup. Malformed, duplicate, or invalid authorization headers never fall back to a local key.
- OIDC role groups cannot overlap, local role-key values must be unique, and the audit key must remain separate from role/provider/safety secrets.
- Admin, Operator, and Viewer keys are compared with `hmac.compare_digest`.
- Viewer can read/export, Operator can also scan and triage alerts, and Admin can also edit asset context, manage policies, and download snapshots.
- Protected operations return HTTP 503 when neither usable enterprise identity nor a valid non-placeholder local role key is configured.
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
- Cross-origin opener/resource isolation and no-cross-domain-policy headers are set.
- Every response receives a generated request ID; logs use route templates and exclude query/body/token data.

### Scan safety

- Scan requests require explicit server-side authorization confirmation.
- Targets are restricted to approved local IPv4 ranges.
- Public and unsupported IPv6 targets are rejected.
- CIDR scans are limited to 256 hosts.
- API requests are rate limited per authenticated identity and route template.
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
- Audit records can contain individual actor, role, authentication method, request ID, action, target, outcome, and short details but never raw keys or bearer tokens.
- New audit records use a separate server-only HMAC key, chained hashes, and a keyed head checkpoint. Readiness and privileged operations verify every retained protected row and pause on changes, broken links, unprotected suffixes, or protected-tail deletion. Pre-v1.6 rows remain explicit legacy evidence.
- Individual audit identities are Admin-only; generated reports use identity-redacted audit rows.
- Existing databases migrate in place at schema version 7.
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

### Optional intelligence boundary

- `OPENAI_API_KEY` is read only by the backend from runtime environment and is excluded from Git and Docker build context.
- End users authenticate to NetWatch and never enter, receive, or call the provider with the provider key.
- An independent server-only safety secret derives a stable opaque deployment subject; roles, usernames, hostnames, and client addresses never feed the provider-visible identifier.
- The de-identification gate sends aggregate counts, known service metadata, operational state, and local case references only.
- IP addresses, CIDRs, hostnames, owners, departments, locations, notes, and raw event details are excluded.
- Snapshot values are treated as untrusted evidence under a fixed defensive instruction; arbitrary prompts and model tools are not supported.
- Requests use strict structured output, response storage disabled, a key-separated opaque safety identifier, bounded timeout/output, a fixed official HTTPS endpoint, and a no-redirect transport.
- Responses are schema-validated before display or storage and cannot directly start scans, modify cases, or execute actions.
- Separate rate and concurrency limits, an atomic UTC day-keyed call budget independent of event/cache retention, and an expiring SQLite cache reduce abuse and cost.
- The dashboard fixes API calls to its own origin and ignores query-string destination overrides before attaching a NetWatch role key.
- SQLite stores bounded status/model/token/cache metadata and structured output, but not the prompt, snapshot, key, safety identifier, or raw network evidence.
- Provider errors are mapped to safe messages; raw upstream bodies are not logged or returned.
- The deterministic local Risk Advisor and all core monitoring workflows remain available without the provider.

### Container controls

- The container runs as a non-root user.
- Docker Compose drops all Linux capabilities and adds only `NET_RAW` for ping.
- `no-new-privileges` is enabled.
- Port `8000` is published only on `127.0.0.1`.
- Local data is persisted in named volumes.
- The image excludes local secrets and generated data through `.dockerignore`.

## Residual risks

- A user with access to the local machine and `.env` can obtain configured role keys.
- Optional local role keys are shared break-glass secrets, not individual identity.
- Localhost binding does not protect against every malicious process running under the same user account.
- ICMP and TCP observations can be incomplete or misleading due to filtering and transient network conditions.
- The in-memory rate limiter resets when the process restarts and is not suitable for a multi-worker deployment.
- SQLite and the current schema are designed for a trusted local pilot, not high-concurrency multi-tenant use.
- The retained audit chain detects changes and protected-tail deletion while its separate key remains protected, but bounded local retention intentionally removes old prefixes and is not a substitute for centralized append-only export.
- Changing or losing the audit HMAC key makes existing protected rows unverifiable and pauses privileged operations; restore the prior key or follow a reviewed archival/reinitialization procedure.
- Change events remain network evidence and can contain sensitive internal addressing even without hostnames.
- Reports and screenshots can expose sensitive internal information if shared carelessly.
- The in-process scheduler is not safe for multi-worker or multi-instance coordination.
- Actions performed with local role keys identify only the shared role; OIDC actions carry the individual subject.
- A downloaded snapshot is not an automated encrypted off-host backup or a tested disaster-recovery plan.
- Local SLA due times are workflow guidance, not an organization-wide incident-management or paging service.
- Maintenance checks depend on the single local process and shared SQLite clock evidence.
- The application daily AI limit is local process/database policy, not a provider billing guarantee; project spend and rate limits must also be configured.
- Identity depends on the reviewed gateway forwarding the intended signed token and the IdP issuing bounded group claims.
- Model recommendations can be incomplete or wrong and require human validation against original local evidence.
- Calling an external provider creates a deployment-specific data-processing and privacy decision even though the default snapshot is de-identified.

## Shared-deployment requirements

Do not expose the default service to other networks without adding:

- TLS
- An approved OIDC-aware TLS gateway and dedicated least-privilege groups
- Controlled, monitored break-glass credential handling
- Managed secrets
- Provider project spend/rate limits and approved data-processing controls
- Network restrictions
- Centralized append-only audit/log export
- External scheduler/worker coordination with leader election
- Centralized monitoring and alert delivery
- Automated encrypted off-host backup, tested restore, and migration procedures
- Retention/deletion policy
- Dependency and container vulnerability management
- A deployment-specific penetration test, AI evaluation, and privacy review

## Review conclusion

NetWatch v1.6 is appropriate as a reviewed single-instance internal deployment foundation when operated according to the enterprise guide. Optional intelligence remains advisory and requires provider billing, privacy, and retention review. NetWatch is not approved as-is for direct Internet exposure, unreviewed multi-tenancy, or multi-replica use against SQLite.
