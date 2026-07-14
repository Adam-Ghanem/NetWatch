# NetWatch v1.1 Demo Script

## 1. Introduction

"NetWatch is a local-first defensive network visibility platform. It helps an authorized operator discover local hosts, track meaningful changes between scans, review common service exposure, maintain an asset inventory, generate local guidance, and export reports."

## 2. Explain the safety boundary

"The application accepts only approved local IPv4 ranges, blocks public targets, limits CIDR size, requires an API key, and asks for explicit authorization before scans. It does not exploit services or test credentials."

## 3. Open the dashboard

1. Start NetWatch with `python scripts/start.py`.
2. Open `http://127.0.0.1:8000`.
3. Enter the API key printed by the launcher.
4. Show that the key is stored only for the browser session.

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
- Recent scan audit trail
- Normalized change history and the evidence recorded for each event

## 9. Risk Advisor

Open **Risk advisor** and explain:

- It is deterministic and local
- It uses saved NetWatch evidence
- It does not send scan data to an external service
- Confidence depends on available data

## 10. Reports

Open **Reports** and download:

- Markdown report
- Standalone HTML report

Explain that reports can contain sensitive internal network information and must be reviewed before sharing.

## 11. Technical architecture

"The dashboard and API are served by one FastAPI process. SQLite stores local inventory, normalized scan observations, change events, and scan history. Docker runs as a non-root user and publishes the application only on localhost by default."

## 12. Close

"NetWatch is designed as a safe local visibility and evidence tool. A shared company deployment would additionally require SSO, roles, TLS, managed secrets, centralized logs, monitoring, backups, and a deployment-specific security review."
