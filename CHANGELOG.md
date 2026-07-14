# Changelog

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
