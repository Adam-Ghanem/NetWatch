# NetWatch Security Assessment Checklist

This checklist is a staging/manual assessment plan. It is not a claim that an independent penetration test has been completed.

## Authentication and authorization

| Test | Expected result | Evidence |
|---|---|---|
| Missing, malformed, expired, wrong-issuer, wrong-audience, unsupported-algorithm, and missing-`kid` bearer tokens | HTTP 401/403 or fail-closed readiness; no shared-key fallback when an invalid bearer is present | Existing automated auth tests plus staging request log |
| Viewer attempts to scan, capture, edit asset context, mutate policy, manage alerts, download backup, or run retention cleanup | Denied server-side; no state change | API response, audit record, and database diff |
| Operator attempts Admin-only actions and cross-resource operations | Denied server-side; no state change | API response and audit record |
| IDOR using another asset, scan, finding, alert, report, or retention identifier | No cross-scope data or mutation | Tenant/resource matrix in staging |

## Input and injection boundaries

| Test | Expected result | Evidence |
|---|---|---|
| Malformed CIDR, oversized CIDR, public IP, IPv6, invalid port/filter, and oversized request fields | Validation failure without subprocess or database side effects | Response and logs |
| SQL-like strings in asset context, report inputs, filters, and webhook configuration | Treated as data; no query or template execution | Automated regression plus staging request sample |
| HTML/script payloads in hostname, notes, evidence, and report fields | Escaped text in API/frontend/report outputs | Browser and downloaded-report inspection |
| Path traversal or filename manipulation in backup/report downloads | Fixed safe filename and bounded content only | Response headers and filesystem review |

## SSRF and outbound integrations

| Test | Expected result | Evidence |
|---|---|---|
| Webhook/event sink URL using HTTP, credentials, fragments, query strings, redirects, loopback, link-local, or private destinations | Rejected or disabled; no credential forwarding | Notification logs and controlled mock server |
| Event sink timeout, oversized response, repeated failure, and retry exhaustion | Bounded retry, circuit break, safe error, no request-thread starvation | Metrics and audit record |
| OIDC JWKS or provider redirect behavior | Redirects refused where required; no bearer leakage | Controlled staging endpoint |

## Resource exhaustion and reliability

| Test | Expected result | Evidence |
|---|---|---|
| Concurrent scan/capture requests above configured semaphore | Bounded rejection without unbounded worker growth | p95/p99, process memory, logs |
| Report generation with maximum retained row counts | Bounded PDF/HTML/Markdown output and predictable latency | Benchmark report |
| Retention cleanup above the configured row cap | No more than the cap is deleted; audit rows remain | Before/after row counts and integrity check |
| Database unavailable, read-only, locked, or partially migrated | Safe readiness/error; no false success; audit behavior documented | Failure-injection record |
| Scan timeout, partial host failure, and worker exception | Partial evidence is explicit; scan does not fabricate identity or downtime | Test output and database diff |

## Secrets and supply chain

| Test | Expected result | Evidence |
|---|---|---|
| Search repository, image, logs, reports, and database for API keys, bearer tokens, provider keys, and audit HMAC material | No secret material present | Redacted scan output |
| Dependency audit and static security scan | No known runtime dependency vulnerabilities and no untriaged high/medium findings | CI artifacts |
| Release image provenance and SBOM | Verified signed digest and attestation before admission | Requires workflow permission and staging release |

## Exit rule

A failed or unexecuted staging/manual item remains an open production-readiness finding. Automated unit tests and local CI are necessary but do not substitute for independent assessment, deployed dependency failure tests, or organization-specific approval.
