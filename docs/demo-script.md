# NetWatch v1.6 Demo Script

## 1. Introduction

"NetWatch is a local-first defensive network visibility platform. It helps an authorized internal team discover local hosts, track meaningful changes, review common service exposure, assign accountable business context, operate approved scan policies, pause work during maintenance, manage alert cases against local SLAs, create consistent snapshots, and export reports and metrics."

## 2. Explain the safety boundary

"The application accepts only approved local IPv4 ranges, blocks public targets, limits CIDR size, requires an API key, and asks for explicit authorization before scans. It does not exploit services or test credentials."

## 3. Open the dashboard

1. Start NetWatch with `python scripts/start.py`.
2. Open `http://127.0.0.1:8000`.
3. Enter the API key printed by the launcher.
4. Show that the key is stored only for the browser session.
5. Show the connected Admin role and explain the Viewer and Operator boundaries.

## 4. Overview

Explain:

- Saved asset count
- Observed open-service count
- Assets with non-zero exposure scores
- Recent checks
- Recent new, returned, and not-observed asset events
- Compact Risk Advisor summary

## 5. Network scan

1. Open **Network scan**.
2. Enter a small authorized range such as `192.168.1.0/28`.
3. Check the authorization confirmation.
4. Start the scan.
5. Explain that ICMP filtering may hide active hosts.
6. Point out the snapshot metrics for observed, new, returned, and not-observed assets.
7. Explain that `Not observed` is cautious wording, not a confirmed offline state.

## 6. Host check

1. Open **Host check**.
2. Enter one known approved local IP.
3. Run the check.
4. Explain latency, TTL, hostname, and the cautious OS hint.

## 7. Port audit

1. Open **Port audit**.
2. Enter one authorized local IP.
3. Run the audit.
4. Explain Open, Closed, and Filtered/Unreachable states.
5. Explain that an open service is exposure requiring context, not automatic proof of a vulnerability.
6. Review priority and recommendation fields.

## 8. Inventory and history

Open **Inventory** and explain:

- First/last seen information
- Saved open ports
- Exposure score and priority
- Owner, department, location, and business criticality
- Recent scan audit trail
- Normalized change history and the evidence recorded for each event

Update one approved sample asset with an owner and criticality, then export the inventory CSV.

## 9. Operations audit log

Open **Audit log** and explain:

- UTC event time
- Actor role and operation
- Target, outcome, and bounded summary
- API keys are never stored in audit records

## 10. Company operations

Open **Operations** first and explain:

- Policies store one immutable Admin-approved private CIDR
- Intervals are bounded from 15 minutes to 7 days
- Scheduled execution is disabled by default and runs only in the single API process
- Manual policy runs require a current authorization confirmation
- Cases are created from saved asset transitions and repeated unresolved findings are deduplicated
- Critical business context raises the priority of a not-observed alert
- Severity sets a local response due time; cases can be assigned, acknowledged, resolved with evidence, and reopened
- Global or policy-specific maintenance windows pause applicable scans
- Authenticated metrics export counters without private target labels

Run a disabled sample policy manually. Create a short maintenance window and show that a policy run is paused, then disable the window. Assign and acknowledge one sample case, resolve it with a note, and show that the actions appear in the audit log. Export metrics, then download a database snapshot and explain that it contains sensitive internal evidence and must be stored encrypted.

## 11. Risk Advisor

Open **Risk advisor** and explain:

- The Risk Advisor is deterministic and local
- It uses saved NetWatch evidence
- It does not send scan data to an external service
- Confidence depends on available data
- Exposed High and Critical assets are prioritized using saved business context

Then show **NetWatch Intelligence** separately:

- The browser never receives or asks for the provider key
- IP addresses, CIDRs, hostnames, owners, departments, locations, notes, and raw event details are excluded before the request
- The provider returns a strict defensive brief and cannot run scans, call tools, or change NetWatch data
- Cache, separate rate/concurrency limits, atomic daily budget, provider redirect refusal, and safe fallback protect the service
- Every recommendation requires human validation against the original local evidence

## 12. Reports

Open **Reports** and download:

- Markdown report
- Standalone HTML report

Explain that reports can contain sensitive internal network information and must be reviewed before sharing.

## 13. Technical architecture

"The dashboard, API, and optional scheduler are served by one FastAPI process. SQLite stores local inventory, business context, normalized observations, change events, approved policies, maintenance windows, alert cases, scan history, and a bounded operations audit log. Docker runs as a non-root user and publishes the application only on localhost by default."

## 14. Close

"NetWatch v1.6 adds verified OIDC identity, individual audit attribution, HMAC integrity, probes, and request observability for a reviewed internal deployment. Its SQLite store, in-process scheduler, application AI budget, and snapshot download are not multi-replica coordination, provider billing control, an external incident platform, or automated disaster recovery; production still requires an approved identity-aware TLS gateway, managed secrets, centralized append-only log export, monitoring, encrypted off-host backups with restore drills, and deployment-specific security, privacy, and AI reviews."
