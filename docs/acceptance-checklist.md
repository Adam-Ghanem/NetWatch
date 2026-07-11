# NetWatch v1 Acceptance Checklist

Use this checklist before merging, presenting, or handing over NetWatch.

## Repository and release

- [ ] README shows NetWatch v1 and the correct startup command.
- [ ] Changelog contains the v1.0.0 release.
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

## Dashboard

- [ ] Desktop navigation works.
- [ ] Mobile navigation remains usable.
- [ ] Overview metrics load without console errors.
- [ ] Refresh and disconnect actions work.
- [ ] Loading and error states are understandable.
- [ ] Dynamic API values are rendered as text, not injected HTML.

## Network workflows

- [ ] Network Scan rejects requests without authorization confirmation.
- [ ] Network Scan works on a small approved IPv4 CIDR.
- [ ] Host Check displays reachability, latency, TTL, hostname, and notes.
- [ ] Port Audit displays service status, response time, priority, and recommendation.
- [ ] Port Audit distinguishes open, closed, and filtered/unreachable states.
- [ ] Inventory displays saved assets and exposure information.
- [ ] History displays recent scan runs.
- [ ] Risk Advisor rebuilds from saved evidence.
- [ ] Markdown report downloads correctly.
- [ ] HTML report downloads and opens correctly.

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
