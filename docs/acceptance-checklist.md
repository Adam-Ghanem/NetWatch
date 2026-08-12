# NetWatch v1.7 Acceptance Checklist

Use this checklist before merging, presenting, or handing over NetWatch.

## Repository and release

- [ ] README shows NetWatch v1.7 and the correct startup command.
- [ ] Changelog contains the v1.7.0 release.
- [ ] Architecture, deployment, and security documentation match the current code.
- [ ] `.env`, database files, logs, and reports are ignored by Git.
- [ ] No real API key or internal network evidence is committed.

## One-command deployment

- [ ] Docker Desktop or Docker Engine is available.
- [ ] `python scripts/start.py` completes successfully.
- [ ] `.env` is created with a generated API key.
- [ ] `.env` contains a distinct generated audit HMAC key that is never printed.
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
- [ ] Host Check displays reachability, latency, TTL, hostname, MAC/manufacturer, device identity, confidence/source, and notes.
- [ ] A same-segment device with neighbor evidence shows a normalized MAC and offline OUI manufacturer.
- [ ] Private/randomized MAC addresses are labeled and do not receive a false hardware-vendor claim.
- [ ] Traffic Explorer rejects requests without authorization and Viewer access.
- [ ] Traffic Explorer enforces interface allowlisting, exact filters, 15-second/1,000-frame limits, and the capture semaphore.
- [ ] Traffic Explorer displays protocol, conversation, endpoint, and packet-header metadata without payload content.
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
- [ ] Both report formats include case/SLA evidence, approved scan policies, and maintenance windows.
- [ ] An existing pre-v1.7 database migrates to schema version 8 without losing saved assets, alerts, or audit rows.
- [ ] Legacy audit rows remain labeled and new rows verify through the HMAC chain.

## Enterprise identity and audit

- [ ] Correct issuer, audience, signature, expiry, issue time, subject, and mapped group authenticate successfully.
- [ ] Wrong issuer/audience, expired tokens, unsupported algorithms, missing key IDs, and attacker-controlled key-reference headers are rejected.
- [ ] A supplied invalid bearer token never falls back to a simultaneously supplied shared key.
- [ ] Unmapped company users receive HTTP 403.
- [ ] Company-session users do not enter a shared NetWatch key or provider key in the dashboard.
- [ ] Viewer and Operator cannot access individual audit identities or the integrity endpoint.
- [ ] Admin sees individual actor, authentication method, request correlation, and audit integrity status.
- [ ] Modifying any retained protected audit field makes integrity verification fail.
- [ ] `/api/health/live` remains process-only and `/api/health/ready` detects database/access/OIDC configuration readiness.
- [ ] Every response has a generated `X-Request-ID`; request logs contain no token, key, query, request body, or private path value.

## NetWatch Intelligence

- [ ] `/api/intelligence/status` and `/api/intelligence/brief` require a valid NetWatch role key.
- [ ] End users can request a brief without entering or receiving `OPENAI_API_KEY`.
- [ ] `OPENAI_API_KEY` is absent from tracked files, browser JavaScript, API responses, logs, reports, database rows, and the Docker image.
- [ ] The launcher creates distinct `NETWATCH_AI_SAFETY_SECRET` and `NETWATCH_AI_SUBJECT_ID` values without printing them; Intelligence fails closed if either is missing or the safety secret equals `OPENAI_API_KEY`.
- [ ] `.env` is ignored by Git and excluded by `.dockerignore`.
- [ ] The provider snapshot contains no IP address, CIDR, hostname, owner, department, location, note, or raw event detail.
- [ ] The request uses a fixed defensive instruction, no tools, no arbitrary user prompt, strict structured output, and response storage disabled.
- [ ] Invalid, refused, timed-out, oversized, rate-limited, or unavailable provider responses fail closed with a safe error.
- [ ] Provider redirects (301, 302, 303, 307, and 308) are refused without forwarding the bearer credential.
- [ ] A provider failure leaves the deterministic local Risk Advisor and core monitoring usable.
- [ ] Repeated requests for unchanged evidence use the bounded cache.
- [ ] Only Admin can force a provider refresh; all authenticated roles can use a valid cached or normal brief.
- [ ] Separate AI rate, concurrency, timeout, output, atomic daily-budget, and retention limits are enforced; concurrent requests cannot exceed the budget and event pruning cannot reset it.
- [ ] Dashboard query parameters and cross-origin configuration cannot change the destination that receives `X-NetWatch-Key`.
- [ ] Intelligence audit/metric records contain only bounded metadata and no high-cardinality target labels.
- [ ] Provider project spend and rate limits are configured outside NetWatch before shared use.
- [ ] A human validates recommendations against the original local evidence before action.

## Company operations

- [ ] Viewer can read policies, cases, SLA state, metrics, and maintenance windows but cannot change them.
- [ ] Operator can run an approved policy only after current authorization confirmation.
- [ ] Operator can assign, acknowledge, resolve with evidence, and reopen cases but cannot create or enable policies or maintenance windows.
- [ ] Admin can create, enable, disable, and update approved policies and maintenance windows.
- [ ] Policy creation rejects missing authorization, public targets, duplicate CIDRs, and intervals below 15 minutes.
- [ ] Policy target CIDR cannot be changed after approval.
- [ ] Scheduled execution remains disabled with the default `.env`.
- [ ] Enabling `NETWATCH_SCHEDULER_ENABLED=true` runs due policies in the single API process.
- [ ] Scheduled policy runs share the configured scan concurrency limit.
- [ ] New, returned, and not-observed transitions create bounded operational cases.
- [ ] Repeated unresolved findings refresh one case and increment its occurrence count.
- [ ] Severity-based due times and overdue state are calculated consistently.
- [ ] A case cannot be resolved without a resolution note.
- [ ] Resolved findings create a new case when the same transition recurs later.
- [ ] A not-observed Critical asset creates a Critical alert without claiming confirmed downtime.
- [ ] Alert acknowledgement records actor role and UTC time.
- [ ] Active global and policy-specific maintenance windows pause applicable scheduler claims.
- [ ] Manual policy execution returns HTTP 409 during applicable maintenance.
- [ ] Maintenance timestamps require timezones and duration cannot exceed 31 days.
- [ ] `/api/metrics` requires authentication and contains no target/IP labels.
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
- [ ] The model cannot choose targets, start scans, mutate cases, call tools, or execute recommendations.
- [ ] Role keys are distinct, at least 32 characters, and not committed.
- [ ] Scheduler is not enabled in a multi-worker or multi-instance deployment.
- [ ] Monitoring metrics are collected only through an authenticated local connection.
- [ ] Downloaded snapshots are treated as sensitive internal data.

## Automated validation

- [ ] `python -m compileall -q .` passes.
- [ ] `node --check frontend/app.js` passes.
- [ ] `docker compose config --quiet` passes.
- [ ] `docker build -t netwatch-local .` passes.
- [ ] `pytest -q` passes.
- [ ] Python CI passes on GitHub.
- [ ] Security CI passes on GitHub.
- [ ] De-identification and secret-boundary regression tests pass.

## Presentation and handover

- [ ] Demo targets and CIDR ranges are explicitly authorized.
- [ ] No sensitive company IP map is shown publicly.
- [ ] Reports are reviewed before sharing.
- [ ] The operator understands that open ports are exposure, not automatic vulnerabilities.
- [ ] The operator understands that blocked ICMP can hide active hosts.
- [ ] Remote/shared deployment requirements are explained separately from the local default.
