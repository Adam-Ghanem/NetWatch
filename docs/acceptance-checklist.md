# NetWatch v1.3 Acceptance Checklist

Use this checklist before merging, presenting, or handing over NetWatch.

## Repository and release

- [ ] README shows NetWatch v1.3 and the correct startup command.
- [ ] Changelog contains the v1.3.0 release.
- [ ] Architecture, deployment, and security documentation match the current code.
- [ ] `.env`, database files, logs, and reports are ignored by Git.
- [ ] No real API key or internal network evidence is committed.

## One-command deployment

- [ ] Docker Desktop or Docker Engine is available.
- [ ] `python scripts/start.py` completes successfully.
- [ ] `.env` is created with a generated API key.
- [ ] `.env` uses private permissions on supported Unix systems.
- [ ] `docker compose ps` shows the `netwatch` service as running/healthy.
- [ ] The dashboard opens at `http://127.0.0.1:8000`.
- [ ] The printed API key connects successfully.
- [ ] Closing the browser tab clears the session-only key.
- [ ] Optional Operator and Viewer keys are blank unless intentionally configured.

## Dashboard

- [ ] Desktop navigation works.
- [ ] Mobile navigation remains usable.
- [ ] Overview metrics load without console errors.
- [ ] Refresh and disconnect actions work.
- [ ] Loading and error states are understandable.
- [ ] Dynamic API values are rendered as text, not injected HTML.
- [ ] The connected role and capabilities are displayed correctly.

## Network workflows

- [ ] Network Scan rejects requests without authorization confirmation.
- [ ] Network Scan works on a small approved IPv4 CIDR.
- [ ] Host Check displays reachability, latency, TTL, hostname, and notes.
- [ ] Port Audit displays service status, response time, priority, and recommendation.
- [ ] Port Audit distinguishes open, closed, and filtered/unreachable states.
- [ ] Inventory displays saved assets and exposure information.
- [ ] Admin can update owner, department, location, criticality, and notes.
- [ ] Operator and Viewer cannot update company asset context.
- [ ] Viewer cannot start scans; Operator and Admin can after explicit authorization.
- [ ] Inventory CSV downloads and formula-like cells are neutralized.
- [ ] A first network scan records newly observed assets.
- [ ] A later missing reply records `Not observed` without changing the last confirmed sighting.
- [ ] A device seen again after an absence records a Returned event.
- [ ] Repeated missing results do not create duplicate transition events.
- [ ] Recent asset changes appear on Overview and Inventory.
- [ ] History displays recent scan runs.
- [ ] Risk Advisor rebuilds from saved evidence.
- [ ] Markdown report downloads correctly.
- [ ] HTML report downloads and opens correctly.
- [ ] Both report formats include recent asset changes.
- [ ] Audit Log records scan and context operations without API keys.
- [ ] Both report formats include recent operations audit events.
- [ ] Both report formats include operational alerts and approved scan policies.
- [ ] An existing pre-v1.3 database migrates to schema version 4 without losing saved assets.

## Company operations

- [ ] Viewer can read policies and alerts but cannot change them.
- [ ] Operator can run an approved policy only after current authorization confirmation.
- [ ] Operator can acknowledge and reopen alerts but cannot create or enable policies.
- [ ] Admin can create, enable, disable, and update approved policies.
- [ ] Policy creation rejects missing authorization, public targets, duplicate CIDRs, and intervals below 15 minutes.
- [ ] Policy target CIDR cannot be changed after approval.
- [ ] Scheduled execution remains disabled with the default `.env`.
- [ ] Enabling `NETWATCH_SCHEDULER_ENABLED=true` runs due policies in the single API process.
- [ ] Scheduled policy runs share the configured scan concurrency limit.
- [ ] New, returned, and not-observed transitions create bounded operational alerts.
- [ ] A not-observed Critical asset creates a Critical alert without claiming confirmed downtime.
- [ ] Alert acknowledgement records actor role and UTC time.
- [ ] Admin can download a non-empty SQLite snapshot that passes `PRAGMA integrity_check`.
- [ ] Viewer and Operator cannot download a database snapshot.
- [ ] Snapshot creation is recorded in the live audit log.

## Safety and security

- [ ] Missing API key returns HTTP 401.
- [ ] Unconfigured server key returns HTTP 503 for protected endpoints.
- [ ] Public IPv4 targets are blocked.
- [ ] Unsupported IPv6 targets are blocked clearly.
- [ ] Oversized CIDR ranges are blocked.
- [ ] Rate limiting returns HTTP 429 when exceeded.
- [ ] Concurrent scan limit prevents overlapping scans.
- [ ] Untrusted browser origins do not receive CORS permission.
- [ ] Dashboard responses include CSP, frame blocking, and MIME-sniffing protection.
- [ ] API responses use `Cache-Control: no-store`.
- [ ] Docker runs as a non-root user.
- [ ] Port `8000` is published only on localhost.
- [ ] No exploitation, brute-force, credential, stealth, or evasion logic exists.
- [ ] Role keys are distinct, at least 32 characters, and not committed.
- [ ] Scheduler is not enabled in a multi-worker or multi-instance deployment.
- [ ] Downloaded snapshots are treated as sensitive internal data.

## Automated validation

- [ ] `python -m compileall -q .` passes.
- [ ] `node --check frontend/app.js` passes.
- [ ] `docker compose config --quiet` passes.
- [ ] `docker build -t netwatch-local .` passes.
- [ ] `pytest -q` passes.
- [ ] Python CI passes on GitHub.
- [ ] Security CI passes on GitHub.

## Presentation and handover

- [ ] Demo targets and CIDR ranges are explicitly authorized.
- [ ] No sensitive company IP map is shown publicly.
- [ ] Reports are reviewed before sharing.
- [ ] The operator understands that open ports are exposure, not automatic vulnerabilities.
- [ ] The operator understands that blocked ICMP can hide active hosts.
- [ ] Remote/shared deployment requirements are explained separately from the local default.
