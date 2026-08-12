# Changelog

## Unreleased

- Added bounded PDF report export and Admin-only retention status, dry-run preview, and confirmed operational cleanup. Cleanup excludes audit-chain evidence and is capped by configured row limits.

- Bulk network scans now perform bounded reverse-DNS enrichment by default, preserve MAC/OUI evidence, and show hostname plus identity source beside device name, MAC address, manufacturer, and confidence in scan and inventory tables. The lookup can be disabled with `NETWATCH_HOSTNAME_LOOKUP_ENABLED=false`.

- Added optional HTTPS generic-webhook and Slack-compatible alert delivery with Admin-only status/test controls, de-identified payloads by default, bounded retries, debounce, response caps, and per-channel circuit breaking.
- Added normalized per-scan service findings for port audits with sanitized protocol, port, service, status, risk, and response-time fields, bounded 50,000-row retention, authenticated filtering, and a dashboard history panel.
- Upgraded SQLite schema tracking to version 9 and added migration, retention, API, and frontend regression coverage for service findings.
- Added the ABC enterprise architecture document with explicit `single_tenant`, `compatibility`, and fail-closed `shared_service` modes.
- Added SQLite-compatible transactional outbox and idempotent job primitives with tenant scope, dedupe keys, leases, bounded attempts, retry state, and dead-letter visibility.
- Added Admin-only `/api/enterprise/status` and authenticated queue gauges for platform readiness without returning secrets or backend URLs; upgraded SQLite schema tracking to version 10.

## v1.7.0

- Added normalized MAC-address discovery from Linux, macOS/BSD, and Windows neighbor-table formats after authorized host checks and local CIDR discovery.
- Added offline IEEE OUI manufacturer lookup, private/randomized MAC detection, hostname-aware device-family inference, cautious iPhone/Redmi and other device hints, and explicit confidence/source evidence.
- Persisted hostname, MAC, manufacturer, device name/type/family, identity confidence/source, and randomized-MAC state in the SQLite asset inventory; upgraded the schema to version 8 with an in-place migration.
- Added an Operator/Admin Traffic Explorer with strict authorization, interface allowlisting, exact IP/port/protocol filters, and a raw Linux Ethernet parser for VLAN, ARP, IPv4/IPv6, TCP, UDP, ICMP, and ICMPv6 headers.
- Added protocol distribution, top-conversation, observed-endpoint, TCP-flag, VLAN, timestamp, and frame-size views without returning or retaining packet payload bytes.
- Bounded captures to 15 seconds, 1,000 matching frames, and one concurrent capture by default; recorded only aggregate metadata and the no-payload result in the protected audit log.
- Updated the responsive dashboard, role capabilities, deployment defaults, documentation, and regression coverage for device identity and packet-metadata analysis.

## v1.6.0

- Redesigned the primary dashboard as a dark liquid-glass SOC command center with a persistent sidebar, compact mobile navigation, official NetWatch identity, focused scan/inventory quick actions, a data-backed seven-day activity chart, exposure distribution, and highest-asset risk gauge.
- Added a keyboard-accessible, role-aware command palette for fast module navigation and safe refresh actions, plus visible protected-data freshness status.
- Replaced the full product screenshot gallery with consistent dark liquid-glass previews that use sample private-network data only.
- Added optional company OIDC/JWT identity with strict HTTPS issuer/JWKS configuration, signature, audience, issuer, expiry, subject, authorized-party, algorithm, and key-header validation.
- Added exact, non-overlapping OIDC group-to-Admin/Operator/Viewer mapping while preserving unique local role keys as an optional break-glass path.
- Added automatic same-origin company-session detection in the dashboard so users behind an approved identity gateway do not enter shared or provider keys.
- Added individual actor IDs, authentication method, and generated request IDs to protected operations.
- Added a separate-key HMAC chain and keyed head checkpoint for new audit events, full retained-chain readiness, tampering/tail-deletion detection, privileged-operation fail-closed behavior, legacy-row labeling, and an Admin-only integrity endpoint/dashboard status.
- Restricted individual audit identities to Admin access and kept reports on redacted audit records.
- Added low-cardinality HTTP request, error, active-request, and duration metrics plus safe route-template correlation logs.
- Added separate public liveness and readiness endpoints, database/auth readiness checks, stronger browser isolation headers, and response request IDs.
- Added an enterprise deployment guide and a non-root, read-only-root Kubernetes single-instance template with secret references, resource controls, probes, and persistent storage.
- Added OIDC, fail-closed bearer precedence, audit integrity, readiness, identity privacy, schema migration, launcher key-separation, and UI regression tests; upgraded SQLite schema to version 7.

## v1.5.0

- Added optional server-side NetWatch Intelligence using the OpenAI Responses API with strict structured output and response storage disabled.
- Added a de-identification gate that excludes IP addresses, CIDRs, hostnames, owners, departments, locations, notes, and raw event details before provider calls.
- Added key-separated safety identifiers derived from an independent server secret and opaque deployment subject, fixed defensive instructions, no model tools, no arbitrary user prompts, and human-review-required output.
- Added separate AI rate and concurrency limits, an atomic day-keyed provider-call budget independent of event retention, bounded response size and timeout, and SQLite-backed cache retention.
- Refused every provider redirect before a follow-up request can carry the bearer credential, and mapped redirects to a safe error.
- Added authenticated intelligence status and brief endpoints while preserving the deterministic local Risk Advisor as a no-provider fallback.
- Added bounded `intelligence_events` metadata and cache storage without prompts, snapshots, API keys, or raw network evidence; upgraded SQLite to schema version 6.
- Added role-aware NetWatch Intelligence dashboard controls and safe DOM rendering for structured observations, limitations, and actions.
- Restricted dashboard API destinations to the page's own origin and removed the query-controlled API override so role keys cannot be redirected cross-origin.
- Kept `OPENAI_API_KEY` server-side through ignored local environment files and runtime-only Compose injection; added CI checks for tracked `.env` files, Docker exclusion, and secret-like key patterns.
- Added de-identification, structured-response, provider-failure, redirect, key-separation, concurrent-budget, cache-retention, role, endpoint, same-origin, and secret-boundary regression tests.
- Updated architecture, deployment, handover, security, advisor, demo, and acceptance documentation for the v1.5 data boundary.

## v1.4.0

- Consolidated repeated unresolved findings into one alert case with occurrence count and last-seen evidence.
- Added severity-based local SLA due times, overdue counters, assignee fields, acknowledgement, resolution notes, and reopen controls.
- Required resolution evidence before an alert case can be closed.
- Added bounded timezone-aware global and policy-specific maintenance windows with a 31-day maximum duration.
- Paused scheduler claims and manual policy execution while applicable maintenance windows are active.
- Added authenticated Prometheus text-format counters without target, IP, hostname, or other high-cardinality labels.
- Added maintenance, SLA, case workflow, and monitoring controls to the responsive Operations dashboard.
- Included case/SLA and maintenance evidence in Markdown and HTML reports.
- Upgraded the SQLite schema to version 5 with an in-place alert-table migration that preserves existing records.
- Added migration, deduplication, resolution, maintenance, RBAC, metrics, API, and report regression tests.

## v1.3.0

- Added Admin-managed scan policies with immutable validated private CIDR scope, bounded 15-minute-to-7-day intervals, and a maximum of 50 saved policies.
- Added an opt-in single-process scheduler that atomically claims due policies and reuses the existing scan concurrency limit.
- Added manual policy execution for Admin and Operator roles with a fresh authorization confirmation.
- Added a bounded operational alert inbox for new, returned, and not-observed asset transitions.
- Added criticality-aware alert severity plus Operator/Admin acknowledgement and reopening controls.
- Added an Admin-only consistent SQLite backup download using the SQLite backup API.
- Added role-aware Operations dashboard controls, scheduler status, policy actions, alert triage, and backup download.
- Included operational alerts and approved scan policies in Markdown and HTML reports.
- Upgraded the SQLite schema to version 4 with safe in-place creation of policy and alert tables.
- Added scheduler, RBAC, alert severity, retention, backup integrity, API, frontend, configuration, and report regression tests.
- Documented the single-process scheduler and snapshot-download boundaries for trusted internal deployments.

## v1.2.0

- Added server-enforced Admin, Operator, and Viewer access tiers while preserving `NETWATCH_API_KEY` as the backwards-compatible Admin key.
- Added a protected session endpoint so the dashboard can display capabilities and disable unauthorized controls.
- Added asset owner, department, location, criticality, operational notes, and context-update timestamps with an in-place SQLite migration for existing databases.
- Added a bounded operations audit log for network scans, host checks, port audits, and asset-context updates without storing API keys.
- Added authenticated audit-log and formula-safe inventory CSV endpoints.
- Added role-aware dashboard controls, asset-context editing, audit-log review, and inventory CSV download.
- Prioritized exposed High and Critical business assets in the deterministic Risk Advisor.
- Included operations audit evidence and company asset context in Markdown and HTML reports.
- Updated the optional Streamlit interface to write and display operational audit records.
- Added role-isolation, migration, retention, export-safety, advisor, API, and report regression tests.
- Documented the boundary between a trusted internal pilot and a full enterprise deployment requiring SSO, TLS, secret management, backups, and centralized monitoring.

## v1.1.0

- Added normalized per-scan network observations and durable asset-change events in SQLite.
- Added change detection for newly observed, returned, and not-observed assets.
- Preserved the last confirmed sighting when a host does not answer and avoided treating a missing ICMP reply as proof that a device is offline.
- Added authenticated change-history and observation API endpoints.
- Added change metrics and event history to the primary dashboard and optional Streamlit interface.
- Included recent asset changes in the Risk Advisor and Markdown/HTML reports.
- Bounded event and observation retention to keep local storage predictable.
- Added transition, schema, API, advisor, and report regression tests.

## v1.0.1

- Updated FastAPI, Starlette, Uvicorn, Pydantic, Streamlit, and pytest to patched releases and separated runtime from development dependencies.
- Enforced strong non-placeholder API keys and explicit HTTP Host/CORS allowlists.
- Added upper bounds for environment configuration, inventory queries, scanner workers, and port timeouts.
- Hardened CSV and Markdown exports against formula and table injection edge cases.
- Kept saved inventory and port findings visible across the legacy dashboard advisor, overview, and reports.
- Improved SQLite upserts so saved status and audit details stay current.
- Sanitized and rotated local activity logs to prevent forged lines and unbounded growth.
- Added formatting, import, lint, typing, dependency audit, Bandit, and container privilege checks to CI.
- Removed an unused legacy marketing image and expanded regression coverage.

## v1.0.0

- Promoted the FastAPI application and responsive web dashboard to the default NetWatch product interface.
- Added complete dashboard workflows for overview, network discovery, host profiling, port audits, inventory, history, Risk Advisor, and report downloads.
- Served frontend and API from one same-origin FastAPI process.
- Added a session-only API-key connection screen and disconnect flow.
- Added loading states, error handling, safe DOM rendering, responsive tables, metrics, and mobile navigation.
- Added defensive response headers including Content Security Policy, frame blocking, MIME-sniffing protection, and no-store API caching.
- Added a cross-platform one-command launcher that generates a secret, builds Docker, and starts NetWatch.
- Simplified Docker Compose to one default production-style service with an optional legacy Streamlit profile.
- Made the unified dashboard the default Docker image command.
- Added frontend JavaScript validation, Docker Compose validation, and production container builds to CI.
- Added dashboard/static-file/security-header tests.
- Updated architecture, deployment, security, README, Makefile, and environment documentation.

## v0.7.1

- Added mandatory API-key protection for non-health API endpoints.
- Restricted CORS to configured local frontend origins.
- Added server-side authorization confirmation for every scan request.
- Added API rate limiting and bounded concurrent scans.
- Disabled API scanning when `NETWATCH_API_KEY` is not configured.
- Disabled FastAPI documentation by default.
- Enforced explicit local IPv4 scope and clear IPv6 rejection.
- Updated saved reports and Risk Advisor to use stored port findings.
- Hardened SQLite with WAL mode, busy timeout, UTC timestamps, and indexes.
- Added non-root Docker execution and local-only port bindings.
- Added `.dockerignore`, `.env.example`, API tests, and security CI.

## v0.7.0

- Added an initial FastAPI backend in `backend/`.
- Added a static frontend foundation in `frontend/`.
- Added FastAPI, Uvicorn, and Pydantic dependencies.
- Added premium UI components and updated the Streamlit design.

## v0.6.0

- Switched the app to an editorial light theme.
- Added oversized hero typography.
- Added paper background with a subtle grid.
- Redesigned metric cards with strong borders and shadow.
- Updated buttons, sidebar and table containers.
- Replaced the README banner with a minimal product-style banner.
- Kept the neutral Risk Advisor wording.

## v0.5.2

- Renamed the advisor feature to Risk Advisor.
- Added `advisory_engine.py`.
- Added `docs/advisory-engine.md`.
- Added `tests/test_advisory_engine.py`.
- Updated app labels and export file names.
- Updated README and security notes with neutral advisor wording.

## v0.5.1

- Added safe text helper for custom Streamlit HTML cards.
- Added safe CSV export helper to reduce spreadsheet formula-injection risk.
- Updated app exports to use sanitized CSV output.
- Updated UI metric cards and custom panels to clean dynamic values before rendering.
- Added security hardening documentation.
- Added tests for safe text and safe CSV helpers.
- Updated README with security notes and v0.5.1 details.

## v0.5.0

- Added local advisory engine.
- Added Risk Advisor page to the Streamlit sidebar.
- Added summary output from scan, port and inventory results.
- Added level explanation, priority findings and suggested next steps.
- Added Markdown export for advisor notes.
- Added advisor documentation.
- Added tests for advisor logic.
- Updated README with advisor integration notes.

## v0.4.0

- Added host profiler with latency, TTL, hostname and OS hint.
- Added raw ping output support for more precise host checks.
- Added service catalog with protocol, description, common role and review guidance.
- Added response time measurement for TCP port checks.
- Added device role hint based on observed open services.
- Updated Streamlit UI to show detailed host and service information.
- Added tests for host output parsing and service catalog logic.
- Updated README with accuracy notes and v0.4.0 feature list.

## v0.3.1

- Added Docker Compose deployment file.
- Added company handover notes.
- Added demo presentation script.
- Added deployment guide.
- Added acceptance checklist.
- Added security review notes.
- Added Kali/fish run guide.
- Added GitHub issue templates for bugs and feature requests.
- Updated README with company-ready documentation section.

## v0.3.0

- Added SQLite-backed local asset inventory.
- Added Inventory page with saved devices, exposure score and open port count.
- Added Network Tools page for CIDR profile, gateway guess, netmask and broadcast address.
- Added risk engine for exposure scoring and top recommendations.
- Added standalone HTML report export.
- Added extra tests for risk scoring, reports and network helper logic.
- Updated README and project structure.

## v0.2.0

- Redesigned Streamlit dashboard with dark interface.
- Added Overview, Reports and Safety pages.
- Added local scan history CSV.
- Added Markdown report generation.
- Updated README with more natural project notes.
- Added report tests.

## v0.1.0

- Initial Streamlit dashboard.
- Added host ping checker.
- Added local CIDR scan.
- Added common port audit.
- Added defensive recommendations.
- Added basic tests and GitHub Actions workflow.
