# NetWatch v1.3 Company Handover

## Product summary

NetWatch is a local network visibility and defensive review application for authorized internal environments. It gives a trusted internal pilot team a clear web dashboard for host discovery, focused device checks, common-service review, accountable asset context, local risk guidance, operations logging, and lightweight report export.

The default product interface and API are served together by FastAPI at:

```text
http://127.0.0.1:8000
```

## Current scope

NetWatch v1.3 provides:

- Protected local dashboard with session-only Admin, Operator, and Viewer access
- Approved private/local IPv4 validation
- Local CIDR discovery up to 256 hosts
- Single-host latency, TTL, hostname, and OS hints
- Concurrent review of a conservative common TCP port list
- Open, Closed, and Filtered/Unreachable result states
- Exposure priority scoring and recommendations
- SQLite asset inventory with owner, department, location, criticality, and notes
- Normalized scan snapshots and new/returned/not-observed asset events
- Bounded operations audit log and formula-safe inventory CSV export
- Admin-approved private CIDR policies with bounded intervals
- Opt-in single-process scheduled execution using the normal scan limit
- Criticality-aware operational alerts with Operator/Admin acknowledgement
- Admin-only consistent SQLite snapshot download
- Deterministic local Risk Advisor
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

The launcher prints the dashboard URL and generated local API key.

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
10. Show transition alerts, acknowledge one sample alert, and explain that `Not observed` requires validation.
11. Download a consistent database snapshot and explain protected storage and staged restoration.
12. Open Audit Log and explain role/action/target accountability without stored keys.
13. Open Risk Advisor to show business-critical asset prioritization.
14. Export the inventory CSV and download Markdown and HTML reports.
15. Explain the role boundary, scan limits, localhost binding, single-process scheduler, and data handling.

## Main files

- `backend/main.py`: FastAPI app, role authorization, API routes, rate limits, security headers, and frontend hosting.
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
- `inventory_store.py`: SQLite inventory, company context, changes, and operations audit persistence.
- `operations_store.py`: approved policies, scheduler claims, alerts, and consistent SQLite snapshots.
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
- Operations audit events and actor roles
- Approved scan policies and execution state
- Operational alerts and acknowledgement evidence
- Internal recommendations

Treat database exports, screenshots, logs, and reports as internal information.

## Default security posture

- Localhost-only service exposure
- Valid Admin, Operator, or Viewer key required
- Viewer is read-only, Operator can run authorized checks and triage alerts, and Admin can edit asset context, manage policies, and download snapshots
- Protected API disabled without at least one configured role key
- Explicit authorization confirmation on scans
- Local IPv4 allowlists
- Public and unsupported IPv6 targets rejected
- Rate and concurrency limits
- Non-root container
- Defensive browser security headers
- No external advisory service or telemetry
- Scheduled execution disabled by default

## Company deployment requirements

Before use by multiple employees or on a remote server, add:

- SSO/OIDC organization authentication with individual identities
- Fine-grained authorization beyond shared role secrets
- TLS and reviewed reverse proxy
- Network allowlists or VPN-only access
- Managed secret storage
- Centralized tamper-resistant audit logs
- Retention and deletion policy
- Automated encrypted off-host backups, restore drills, and migrations
- Health monitoring and alerting
- Vulnerability and dependency management
- Formal security and privacy review

## Recommended next product improvements

- Normalized service findings per scan run
- Configurable retention and cleanup controls
- PDF reports
- ARP discovery where permissions allow
- Progress and cancellation for long scans
- SSO/OIDC and individual RBAC for shared deployments
- External scheduler/worker coordination for multi-instance deployment
- Automated encrypted backup rotation and tested restoration
