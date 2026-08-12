# NetWatch Enterprise Operations and Readiness

## Operating intent

NetWatch is a defensive internal service. Production operation requires a named service owner, an identity owner, a platform owner, a data-retention owner, and an incident commander rotation. The service must never be promoted on the basis of application tests alone; the deployment, data, network-scope, recovery, privacy, and supply-chain controls must be reviewed together.

Google SRE guidance distinguishes service-level indicators, objectives, and agreements and recommends selecting a small set of representative indicators rather than tracking every possible metric [3]. NetWatch adopts that approach for the proposed targets below; the business owner must approve the values before production.

## Proposed SLO baseline

| Service behavior | SLI | Initial target | Evidence |
|---|---|---:|---|
| API availability | Successful well-formed protected API requests | ≥ 99.9% monthly for Stage A; ≥ 99.5% for Stage B | HTTP metrics, gateway metrics, synthetic checks |
| API latency | Protected read request p95 | ≤ 500 ms excluding scans and reports | Gateway and application histograms |
| Scan execution | Approved jobs reaching a terminal state | ≥ 99% within the configured job deadline | Job table, worker metrics, audit events |
| Event delivery | Outbox events delivered or dead-lettered with evidence | ≥ 99% within 5 minutes | Outbox state, sink acknowledgements |
| Audit export freshness | Time since last successful append-only export | ≤ 5 minutes in Stage A; ≤ 24 hours in Stage B | Export checkpoint and alert |
| Data durability | Successful backup/replication verification | RPO ≤ 15 minutes in Stage A; RPO ≤ 24 hours in Stage B | Managed database/object-store evidence |
| Recovery | Restore or failover to a usable service | RTO ≤ 60 minutes in Stage A; RTO ≤ 4 hours in Stage B | Quarterly recovery drill |

These are proposed operating targets, not guarantees. An SLO miss must create an operational review and may pause feature promotion or broadened scan scope until the error budget is understood.

## Production-readiness review

Before Stage A promotion, reviewers must confirm that the signed image digest, source and image SBOM, provenance attestation, dependency policy, migration checksum, and configuration bundle are recorded. The identity gateway must enforce TLS, approved OIDC claims, least-privilege groups, session policy, and emergency access procedures. PostgreSQL, Redis, object storage, and the event sink must each have an owner, backup/retention policy, health evidence, and tested failure behavior.

The platform review must verify that API replicas are stateless, worker leases are bounded and renewable, jobs are idempotent, retry storms are capped, dead-letter events have an owner, and no worker can select an arbitrary network target. The data review must verify tenant/resource scope, encryption and key rotation, retention/deletion policy, export controls, and recovery from a staging backup. The security review must verify that traffic capture remains metadata-only, payloads are never persisted, outbound notifications remain redacted by default, and advisory intelligence cannot start scans or mutate cases.

## Incident response

When readiness fails, keep liveness separate from dependency health and stop automated promotion. When audit integrity fails, pause privileged mutations and preserve the database and audit key for forensic review. When the queue grows or dead-letter counts increase, stop increasing worker concurrency, inspect the sink or dependency, replay only idempotent events, and record the operator decision. When a scan scope or authorization issue is suspected, disable the affected policy, preserve approval evidence, and do not broaden the target to restore apparent coverage.

For a suspected credential or signing-key compromise, revoke or rotate the affected secret through managed secret storage, invalidate the associated identity or webhook, preserve redacted audit evidence, and run a post-rotation readiness check. Never place replacement secrets in Git, an image layer, a ticket, or a report.

## Recovery drills

Stage B must complete a quarterly SQLite snapshot restore drill in an isolated environment, including `PRAGMA integrity_check`, application readiness, inventory, policy, alert, audit-integrity, and report checks. Stage A must complete quarterly database failover, worker lease recovery, object-store retrieval, event replay, and identity-gateway dependency drills. Each drill produces an evidence record containing the start/end time, operator, version/digest, observed RTO/RPO, failures, and follow-up owner.

## Change management

Schema changes require a forward migration, a rollback or compatibility statement, a staging backup, and contract tests against the previous supported version. Changes to network scope, sensor capabilities, outbound destinations, identity-group mapping, or retention are security-relevant and require explicit approval. Release promotion requires the exact signed image digest and attestation verification; mutable tags are not production evidence.

## References

[1]: https://www.nist.gov/publications/zero-trust-architecture "NIST Zero Trust Architecture"
[2]: https://slsa.dev/ "SLSA Supply-chain Levels for Software Artifacts"
[3]: https://sre.google/sre-book/service-level-objectives/ "Google SRE: Service Level Objectives"
