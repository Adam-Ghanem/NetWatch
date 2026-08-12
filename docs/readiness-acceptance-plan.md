# A-Then-B Readiness Acceptance Plan

## Purpose

The user selected the staged path: first certify the hardened single-tenant profile, then certify the shared-service enterprise profile. Each profile has its own readiness score. A score reaches 100% only when every required control has an attached implementation, test, staging result, or accountable sign-off.

## Track A — Hardened single-tenant production

| Dimension | Exit criteria | Evidence owner |
|---|---|---|
| Security | Authentication/authorization matrix passes; staging manual assessment closes all Critical/High findings; secrets are absent from code, image, logs, and reports. | Security owner |
| Reliability | Database outage, lock, timeout, partial scan, report failure, and retention failure paths are tested; health/readiness behavior is verified. | QA/Reliability owner |
| Recovery | Encrypted off-host backup rotation exists; restore drill succeeds on an isolated copy; RTO/RPO are measured and approved. | SRE/Operations owner |
| Performance | Benchmark covers authenticated health, inventory, reports, retention preview, and representative approved scan workloads with p50/p95/p99, throughput, error rate, CPU, and memory. | SRE/Performance owner |
| Governance | Retention schedule, access review, incident runbook, change approval, evidence ownership, and claim matrix are complete. | Compliance/Docs owner |
| Deployment | Single-tenant Kustomize/Compose deployment passes staging install, upgrade, rollback, backup, and restore checks. | Platform owner |

**Track A approval rule:** the deployment remains one active application instance per database. It is not allowed to claim multi-tenant isolation or active-active HA.

## Track B — Shared-service enterprise production

| Dimension | Exit criteria | Evidence owner |
|---|---|---|
| Data plane | PostgreSQL migrations, connection pooling, tenant context, row/resource isolation, tenant-scoped retention, tenant-scoped reports, and rollback checks pass. | Backend/Data owner |
| Distributed execution | Redis/PostgreSQL leases, external workers, outbox delivery, idempotency, retries, dead-letter handling, quotas, and leader-election behavior pass failure tests. | Backend/SRE owner |
| Security | OIDC/group mapping, IDOR matrix, injection/SSRF checks, secret rotation, network policy, independent or approved third-party assessment, and retest are complete. | Security owner |
| Scale | Staging benchmark covers concurrent users, scans, reports, alerts, retention, database contention, dependency degradation, and worker restart. SLOs are met at the declared capacity. | SRE/Performance owner |
| Recovery | Managed backups/object storage, restore/replay, regional or zone failure procedure, RTO/RPO, audit export continuity, and incident exercise are complete. | SRE/Operations owner |
| Platform | Signed image digest, SBOM/provenance verification, managed secrets, resource profiles, HPA behavior, rollout/rollback, PDB, network policies, and staging promotion are proven. | DevOps/Platform owner |
| Governance | Tenant data classification, retention/legal hold, access reviews, incident ownership, change records, evidence archive, and claim-to-evidence matrix are approved. | Compliance/Docs owner |

**Track B approval rule:** `shared_service` readiness may only become ready after all Track B Critical/High evidence is attached. A reference manifest, adapter class, or passing unit test alone is insufficient.

## Evidence package required for either score

Each track must publish a release package containing the scorecard, test report, benchmark report, security assessment/retest, backup/restore record, deployment manifest and digest, change record, incident owner, and residual-risk approval. Missing evidence is scored as incomplete rather than assumed to pass.

## Current baseline

Track A now has local isolated evidence for API p50/p95/p99 benchmarks, SQLite snapshot/restore integrity, post-restore readiness/inventory access, and Admin/Operator/Viewer endpoint boundaries. It still requires target-environment deployment approval, off-host encrypted backup rotation, managed-key recovery, representative approved scan/load evidence, independent or approved manual security assessment, and accountable sign-off. Track B remains blocked by the real PostgreSQL tenant model, distributed execution validation, staging scale data, recovery drills, and supply-chain promotion controls. The current repository therefore does not claim 100% for either track yet.
