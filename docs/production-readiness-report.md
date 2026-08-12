# NetWatch Production Readiness Report

**Assessment type:** Pre-change engineering and security audit  
**Assessment date:** 2026-08-12  
**Assessor:** Manus AI  
**Repository baseline:** `main` at the enterprise ABC foundation and scan identity/reporting upgrades  
**Scope:** Authentication and authorization, data isolation, secrets, injection surfaces, deployment controls, reliability, backup/recovery, documentation accuracy, and evidence-backed release readiness.

## Executive conclusion

NetWatch is a defensible **single-instance internal monitoring foundation** with strong authorization boundaries, bounded defensive network operations, protected audit evidence, and passing automated checks. It is **not yet production-ready as a multi-tenant, multi-replica enterprise service**. The current shared-service code is a fail-closed adapter seam, not a validated PostgreSQL/Redis/S3 deployment. The Kubernetes manifest is a reference and is intentionally not deployable without completing migration, tenant-policy, secret, image-integrity, failure-injection, and recovery validation.

The recommendation is to keep the default deployment in the hardened single-tenant profile, block `shared_service` readiness until the missing controls are proven, and execute the remediation roadmap in priority order. The percentages below are engineering readiness indicators, not a certification, audit opinion, or SOC 2/ISO/Google approval.

## Evidence already present

The baseline has **223 automated tests passing** on the local checkout, with Python and Security CI passing on GitHub for the last merged release. Existing controls include role-based access, authorization-first private CIDR validation, bounded scan and capture limits, no-payload traffic metadata, audit-chain integrity checks, safe secret handling, request correlation, authenticated metrics, retention bounds, fail-closed shared-service probes, and runtime dependency auditing.

The repository contains an ABC architecture document, a single-tenant fallback overlay, a shared-service Kubernetes reference, durable outbox/job primitives, optional backend adapters, SLO/recovery guidance, report exports, and acceptance checklists. These artifacts are useful foundations, but they do not replace evidence from a real shared database, multi-tenant integration tests, load benchmarks, independent security testing, or restore drills.

## Findings and prioritization

CVSS is designed for vulnerabilities with an exploitable attack path. Several findings below are **capability or evidence gaps**, so a numeric CVSS score would create false precision. Those items are explicitly marked `N/A` and receive an impact-based priority instead.

| ID | Finding | Priority | CVSS / impact basis | Required evidence before production claim |
|---|---|---:|---|---|
| F-01 | Real PostgreSQL migration, tenant-aware schema, and enforced tenant isolation are not implemented. SQLite remains the default and the shared-service adapters are fail-closed seams. | Critical | CVSS `N/A` for an unimplemented capability; potential impact is critical because a future shared deployment without row-level tenant enforcement could expose another tenant's inventory, alerts, or audit metadata. | PostgreSQL schema and migrations, tenant context propagation, negative isolation tests, connection-pool behavior, migration rollback tests, and authorization tests across every read/write path. |
| F-02 | Multi-replica shared-service execution is not proven. External workers, distributed rate/quota state, leader election, and end-to-end outbox delivery are not validated under failure. | High | CVSS `N/A`; high availability and consistency impact if operators scale the reference manifest before the shared contracts are proven. | Failure-injection tests, worker lease tests against Redis/PostgreSQL, duplicate-delivery tests, split-brain checks, and recovery evidence. |
| F-03 | No repeatable load or scale benchmark exists for concurrent scans, users, API latency, or database stress. | High | CVSS `N/A`; high operational impact because capacity and SLO claims cannot be defended with measured p50/p95/p99 or throughput data. | Locust or k6 scenarios, fixed environment description, p50/p95/p99 latency, throughput, error rate, saturation point, and before/after regression report. |
| F-04 | No independent third-party penetration test or structured OWASP ZAP/manual assessment has been completed. | High | CVSS `N/A`; high assurance impact because automated tests do not prove resistance to auth bypass, IDOR, injection, CSRF, SSRF, or secret-exposure chains. | Scope-approved test plan, staging evidence, findings with CVSS where applicable, remediation verification, and retest sign-off. |
| F-05 | Off-host encrypted backup rotation and tested restoration are documented as requirements but not evidenced as an executed drill in this repository. | High | CVSS `N/A`; high availability and integrity impact if a local SQLite file, key, or host is lost. | Encrypted backup job, key-management procedure, restore drill, integrity check, RTO/RPO measurements, retention/deletion evidence, and operator sign-off. |
| F-06 | The enterprise Kubernetes reference includes conservative resource requests/limits, but no measured resource profile, HPA policy, or staging promotion pipeline is evidenced. | Medium | CVSS `N/A`; medium reliability impact through unverified autoscaling and rollout capacity. | Resource profiles from load tests, HPA behavior under load, PodDisruptionBudget validation, staging deployment, rollback test, and promotion approval. |
| F-07 | Supply-chain SBOM/provenance workflow is not present on GitHub because the connected credential lacks workflow-file permission. Existing Python and Security CI remain active and passing. | Medium | CVSS `N/A`; medium release-integrity impact because provenance and attestation are not enforced by repository CI. | Workflow added with appropriate GitHub permission, signed image digest, SBOM, provenance attestation, verification job, and protected release rule. |
| F-08 | Some documents use “enterprise” or “shared-service” language while also correctly stating that the deployment is a reference and not ready as-is. The wording must remain bounded and every production claim must point to evidence. | Medium | CVSS `N/A`; medium governance impact through accidental overclaiming and unsafe operator interpretation. | Documentation review, claim-to-test matrix, explicit readiness status, and a release scorecard attached to every production artifact. |
| F-09 | API/report and retention controls are tested locally, but a full staging integration test with realistic data volume, degraded dependencies, and restore/replay paths is not yet present. | Medium | CVSS `N/A`; medium reliability impact because local unit/API tests do not cover deployment wiring and operational degradation. | Staging runbook, seeded synthetic-but-representative data, dependency outage tests, report/retention verification, and post-test cleanup. |

## Security audit summary

Authentication and authorization are the strongest part of the current baseline. The application has distinct role capabilities, server-side authorization, explicit authorization for network operations, and fail-closed behavior when usable credentials are not configured. The audit-chain design and no-payload traffic boundary are meaningful controls. They should continue to be treated as evidence-backed safeguards rather than a substitute for an independent penetration test.

The main security risk is not an immediately demonstrated exploit in the default single-instance profile. It is **premature activation of shared-service mode** without tenant isolation, externalized coordination, migration validation, and failure testing. The current fail-closed readiness behavior is therefore a required safety control and must not be relaxed merely to make a Kubernetes manifest appear ready.

The primary testing gap is external assurance. A manual review should explicitly cover token confusion and group mapping, IDOR across asset/report/retention endpoints, SQL/query construction, SSRF and redirect behavior in notification/event sinks, path and file handling for reports/backups, request-size and rate-limit exhaustion, and secrets in logs, images, generated reports, and CI artifacts.

## Reliability and scale assessment

The current design is appropriate for a bounded single-instance deployment. It provides local queue primitives, scan concurrency limits, retention caps, and operational metrics, but it does not yet prove shared-service scalability. The presence of a Kubernetes reference with two replicas must not be interpreted as evidence that the application is safe to scale horizontally against SQLite or that external adapters are production-ready.

A valid benchmark must measure the actual deployment profile, not only call pure Python functions. It should include concurrent authenticated users, small and maximum allowed private CIDR scans, report generation, retention preview, alert transitions, database contention, dependency timeouts, and worker restarts. Results must report p50/p95/p99 latency, throughput, error rate, CPU, memory, database connections, queue age, and recovery time.

## Compliance-style control checklist

| Control family | Current status | Evidence needed for a production claim |
|---|---|---|
| Access control | Partially evidenced | OIDC/group mapping test matrix, break-glass procedure, periodic access review, and staging penetration retest. |
| Auditability | Strong single-instance foundation | Central append-only export, retention/legal-hold policy, alerting on integrity failures, and restore verification. |
| Data lifecycle | Implemented bounded local controls | Organization-approved retention schedule, deletion approvals, backup deletion behavior, and tenant-scoped lifecycle rules. |
| Secrets | Partially evidenced | Managed secret provider integration, rotation drill, image/log scanning, and CI policy enforcement. |
| Change management | Partially evidenced | Staging promotion, protected releases, signed artifacts, rollback approval, and production change records. |
| Resilience | Foundation only | Off-host encrypted backups, restore drill, RTO/RPO measurements, dependency outage tests, and incident exercises. |
| Privacy | Strong defensive boundary in code | Organization-specific privacy review, lawful basis/retention decision, and review of hostname/MAC/report handling. |

## Readiness scorecard

These are provisional engineering scores based on repository evidence, not certification percentages.

| Dimension | Score | Interpretation |
|---|---:|---|
| Security controls | 68% | Strong local authorization and defensive boundaries; independent testing and shared-service isolation remain open. |
| Scale and performance | 28% | Bounded single-instance behavior exists; no representative load benchmark or proven distributed data plane. |
| Reliability and recovery | 49% | Health, metrics, backup endpoint, queue seams, and runbooks exist; restore drills and failure-injection evidence are missing. |
| Compliance and governance | 55% | Audit and retention foundations exist; control ownership, central export, managed secrets, and evidence review are incomplete. |
| **Overall production readiness** | **50%** | Suitable for a reviewed single-instance internal pilot; not approved as-is for multi-tenant or multi-replica production. |

## Remediation roadmap

### Phase 0 — Freeze claims and establish evidence

Immediately mark the current deployment as **single-instance internal pilot** in operator-facing documentation. Add a claim-to-test matrix, preserve the fail-closed shared-service gate, and record the current scorecard as a baseline.

### Phase 1 — Security assurance

Run a scoped staging assessment covering authentication, authorization, IDOR, injection, SSRF, secret exposure, report/backups, rate limits, and denial-of-service boundaries. Convert exploitable findings into tracked issues with CVSS v3.1 scoring where applicable, then retest after remediation.

### Phase 2 — Data-plane readiness

Implement PostgreSQL migrations and tenant context enforcement only after the data model and authorization matrix are reviewed. Add negative isolation tests for assets, scans, findings, alerts, reports, retention, jobs, and audit exports. Add connection-pool limits and a tested rollback strategy.

### Phase 3 — Reliability and scale evidence

Add external worker coordination, distributed quotas, and the failure semantics required by shared-service mode. Run baseline and regression benchmarks with fixed test data and environment descriptions. Do not increase replicas or remove fail-closed readiness until these results meet declared SLOs.

### Phase 4 — Platform and recovery

Add measured resource requests/limits, HPA policy, staging deployment, protected promotion, signed image/SBOM verification, encrypted off-host backups, restore drills, and RTO/RPO evidence. Keep a hardened single-tenant profile as the rollback path.

### Phase 5 — Production readiness review

The compliance/documentation lead updates every claim, attaches the security retest, benchmark report, recovery evidence, and control-owner sign-off, then recalculates the scorecard. Production approval requires explicit acceptance of residual risk by the organization's accountable owner.

## Final decision

**Decision: Do not approve NetWatch for multi-tenant or multi-replica production yet.** Approve continued development and a controlled single-instance internal pilot under the existing authorization, network, secret, audit, and backup procedures. No code change should relax the shared-service fail-closed boundary until the Critical and High findings have concrete evidence attached.
