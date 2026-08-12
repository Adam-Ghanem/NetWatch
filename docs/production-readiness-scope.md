# Production Readiness Scope

This document translates the attached team prompt into an evidence-first execution scope. It deliberately separates repository-verifiable improvements from work that requires a real staging environment, managed infrastructure, or an independent assessor.

## Immediate repository scope

| Priority | Workstream | Deliverable in this repository | Exit evidence |
|---|---|---|---|
| Critical | Security and claims | Pre-change production-readiness report; bounded documentation; explicit fail-closed shared-service status; claim-to-test matrix. | Report committed; docs no longer imply unvalidated HA or compliance. |
| High | QA/reliability | Failure-path tests for database access, retention, report rendering, queue state, scan failure, and authorization; deterministic test fixtures. | Full test suite remains green and failure cases are explicit. |
| High | Platform hardening | Add conservative resource requests/limits and security-context checks to the Kubernetes reference; keep HPA and shared-service rollout gated until benchmark evidence exists. | Manifest validation and documentation clearly label the manifest as reference-only. |
| High | Recovery | Add a repeatable backup verification/restore-check utility and document RTO/RPO evidence collection without claiming a completed off-host drill. | Utility tests pass; operator runbook distinguishes local verification from real restore evidence. |
| Medium | Performance | Add a bounded benchmark harness for authenticated API health, inventory, report, and retention-preview requests. Do not run broad network scans automatically. | Baseline report contains real p50/p95/p99, throughput, error rate, and test environment. |
| Medium | Security assurance | Add a structured manual security-test checklist covering auth bypass, IDOR, injection, SSRF, secret exposure, report/download handling, and rate limits. | Each check links to an automated test or is explicitly marked requiring staging/manual execution. |

## Deferred infrastructure scope

The following items are not safe to claim complete from this repository alone and remain gated roadmap work:

1. A real PostgreSQL/Alembic migration with tenant-aware schema and negative isolation tests across every resource.
2. Active-active multi-replica execution with external workers, distributed quotas, leader election, and failure-injection evidence.
3. A representative Locust/k6 benchmark against a deployed staging environment, including concurrent scans and database saturation.
4. Independent OWASP ZAP/manual penetration testing and remediation retest.
5. Managed secrets/Vault integration, off-host encrypted backup rotation, tested restoration, and measured RTO/RPO.
6. GitHub SBOM/provenance attestation workflow, which requires a credential with workflow-file permission.

## Release rule

No deferred item may be described as complete merely because a reference adapter, Kubernetes manifest, unit test, or documentation section exists. Shared-service readiness remains fail-closed. The production-readiness scorecard must be recalculated only after the corresponding evidence is attached.
