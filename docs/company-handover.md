# NetWatch v1.7 Company Handover

## Product summary

NetWatch is a local network visibility and defensive review application for authorized internal environments. It gives a trusted internal pilot team a clear web dashboard for host discovery, device-identity evidence, bounded traffic-metadata analysis, focused device checks, common-service review, accountable asset context, local risk guidance, operations logging, and lightweight report export.

The default product interface and API are served together by FastAPI at:

```text
http://127.0.0.1:8000
```

## Current scope

NetWatch v1.7 provides:

- Protected dashboard with automatic company SSO detection and local role-key fallback
- Strict OIDC token verification and exact company-group role mapping
- Approved private/local IPv4 validation
- Local CIDR discovery up to 256 hosts
- Single-host latency, TTL, hostname, MAC/manufacturer/device identity, confidence/source, and OS hints
- Offline OUI manufacturer lookup, private-MAC detection, and cautious iPhone/Redmi and other device-family hints
- Operator/Admin Traffic Explorer with bounded Linux header capture, exact filters, protocol/conversation/endpoint summaries, and no payload retention
- Concurrent review of a conservative common TCP port list
- Open, Closed, and Filtered/Unreachable result states
- Exposure priority scoring and recommendations
- SQLite asset inventory with owner, department, location, criticality, and notes
- Normalized scan snapshots and new/returned/not-observed asset events
- Admin-only individual audit identity, request correlation, and separate-key HMAC verification
- Formula-safe inventory CSV export
- Admin-approved private CIDR policies with bounded intervals
- Opt-in single-process scheduled execution using the normal scan limit
- Deduplicated operational cases with occurrence count, assignee, local SLA, acknowledgement, resolution evidence, and reopening
- Bounded global and policy-specific maintenance windows that pause policy execution
- Authenticated label-free operational metrics for a local collector
- Admin-only consistent SQLite snapshot download
- Deterministic local Risk Advisor
- Optional server-side NetWatch Intelligence using aggregated, de-identified evidence, strict structured output, bounded usage, and local fallback
- Markdown and standalone HTML reports
- Docker deployment and one-command launcher
- Automated API, frontend, security, and container validation

## What NetWatch is not

NetWatch is not intended for:

- Public Internet scanning
- Vulnerability exploitation
- Password or credential attacks
- Stealth or evasion
- Malware execution
- Enterprise CMDB replacement
- Multi-tenant production use without additional controls
- Full vulnerability-management replacement

## Installation for an internal demo

```bash
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
python scripts/start.py
```

The launcher prints the dashboard URL but never prints generated credentials. The local break-glass Admin key remains only in the private `.env` file; company SSO users never receive NetWatch or provider keys.

## Suggested demonstration flow

1. Open `http://127.0.0.1:8000`.
2. Enter the generated API key.
3. Explain the Overview metrics and recent activity.
4. Run Network Scan on a small approved range such as `/28`.
5. Run Host Check on a known router, VM, or lab server.
6. Run Port Audit on one known authorized host.
7. Explain why an open service is exposure—not automatic proof of a vulnerability.
8. Open Inventory, assign an owner and criticality, and show scan-to-scan changes.
9. Open Operations, save a disabled approved policy, then explain scheduler opt-in and the immutable CIDR approval record.
10. Create a short maintenance window, show the policy pause, then disable the window.
11. Show a deduplicated case, assign it, acknowledge it, and resolve it with evidence; explain that `Not observed` requires validation.
12. Export authenticated metrics and confirm that they contain counters but no target labels.
13. Download a consistent database snapshot and explain protected storage and staged restoration.
14. Open Audit Log and explain role/action/target accountability without stored keys.
15. Open Risk Advisor to show business-critical asset prioritization.
16. Open NetWatch Intelligence, explain the excluded fields, generate a structured brief, and confirm that the user never enters a provider key.
17. Export the inventory CSV and download Markdown and HTML reports.
18. Explain the role boundary, scan limits, localhost binding, single-process scheduler, provider budget, and data handling.

## Main files

- `backend/main.py`: FastAPI app, role authorization, API routes, request correlation, probes, metrics, security headers, and frontend hosting.
- `enterprise_auth.py`: OIDC/JWKS validation and exact group-to-role mapping.
- `frontend/index.html`: dashboard structure.
- `frontend/styles.css`: responsive visual system.
- `frontend/app.js`: dashboard behavior and protected API workflows.
- `scripts/start.py`: secure one-command Docker launcher.
- `security.py`: local IPv4 target restrictions and review guidance.
- `network_scanner.py`: local host discovery.
- `host_profiler.py`: detailed single-host observations.
- `port_scanner.py`: bounded common-service review.
- `risk_engine.py`: exposure scoring.
- `advisory_engine.py`: local evidence-based summary.
- `ai_advisor.py`: de-identification, fixed defensive provider request, key-separated opaque safety identifier, redirect refusal, and structured response validation.
- `intelligence_store.py`: bounded provider-call metadata, atomic day-keyed budget evidence, and expiring structured brief cache.
- `inventory_store.py`: SQLite inventory, company context, changes, and operations audit persistence.
- `operations_store.py`: approved policies, maintenance-aware scheduler claims, case/SLA workflow, metrics, and consistent SQLite snapshots.
- `report_builder.py`: Markdown and HTML exports.
- `docs/architecture.md`: current technical design.
- `docs/deployment.md`: operating and deployment guide.
- `docs/acceptance-checklist.md`: pre-demo and pre-release checks.

## Operational data

NetWatch stores internal evidence in SQLite. Docker Compose persists it in a named volume.

This information may include:

- Private IP addresses
- Hostnames
- Scan timestamps
- Per-scan presence observations and asset-change events
- Observed service exposure
- Asset owners, departments, locations, criticality, and operational notes
- Integrity-protected operations audit events, actor identities, roles, and request IDs
- Approved scan policies and execution state
- Operational cases, repeated-occurrence/SLA evidence, assignment, acknowledgement, and resolution notes
- Maintenance windows and their change reasons
- Internal recommendations
- De-identified structured intelligence briefs and bounded provider-call metadata

Treat database exports, screenshots, logs, and reports as internal information.

## Default security posture

- Localhost-only service exposure
- Verified company identity or valid local Admin, Operator, or Viewer key required
- Viewer is read-only, Operator can run authorized checks and triage cases, and Admin can edit asset context, manage policies/maintenance, and download snapshots
- Protected API disabled without usable OIDC mapping or a configured local role key
- Explicit authorization confirmation on scans
- Local IPv4 allowlists
- Public and unsupported IPv6 targets rejected
- Rate and concurrency limits
- Non-root container
- Defensive browser security headers
- Deterministic advisor stays local; optional intelligence sends only documented de-identified aggregates when requested
- Provider key is backend-only and excluded from Git, Docker images, browser code, logs, reports, and SQLite
- Scheduled execution disabled by default

## Company deployment requirements

Before use by multiple employees or on a remote server, configure and review:

- The built-in OIDC verifier behind an approved identity-aware TLS gateway
- Dedicated least-privilege IdP groups and controlled break-glass keys
- Network allowlists or VPN-only access
- Managed secret storage
- Provider spend/rate controls and approved AI/data-processing policy
- Centralized append-only export of the locally integrity-protected audit stream
- Retention and deletion policy
- Automated encrypted off-host backups, restore drills, and migrations
- Health monitoring and alerting
- Vulnerability and dependency management
- Formal security and privacy review

## Recommended next product improvements

- Normalized service findings per scan run
- Configurable retention and cleanup controls — delivered with Admin-only status, dry-run preview, explicit confirmation, row caps, and audit-chain protection.
- PDF reports — delivered in the next-release bundle with bounded export rows and the same redacted report inputs.
- ARP discovery where permissions allow
- Progress and cancellation for long scans
- PostgreSQL/distributed coordination for multi-replica deployments
- External scheduler/worker coordination for multi-instance deployment
- Automated encrypted backup rotation and tested restoration
- Representative intelligence evaluations, privacy review, and centralized cost monitoring
