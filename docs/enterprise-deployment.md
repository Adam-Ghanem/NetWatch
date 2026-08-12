# Enterprise deployment guide

NetWatch v1.7 provides enterprise-oriented identity, audit-integrity, device-identity correlation, bounded traffic-metadata visibility, observability, durable outbox/job seams, and container controls for a reviewed **single-instance internal deployment**. It is not approved as-is for multi-tenant or multi-replica production. The current SQLite persistence and in-process scheduler design is intentionally single-instance; this guide does not claim high availability. See [enterprise ABC architecture](enterprise-abc-architecture.md) and the [production-readiness report](production-readiness-report.md) for the evidence-gated migration path.

## Recommended topology

```text
Employee browser
    -> Company identity-aware gateway (TLS, login, session, access token)
    -> Cluster-internal NetWatch service
    -> SQLite persistent volume
    -> Optional approved AI provider over HTTPS
```

The gateway owns the interactive OIDC Authorization Code flow and forwards a signed bearer token to NetWatch. NetWatch never accepts unsigned identity headers. It validates the token signature through the configured HTTPS JWKS endpoint and requires the exact issuer, audience, allowed asymmetric algorithm, expiry, issue time, subject, and mapped group.

The browser does not store the bearer token in NetWatch JavaScript. The gateway attaches it to same-origin requests. NetWatch automatically detects the resulting company session through `/api/session`. Local role keys can remain disabled or be held as controlled break-glass secrets.

## Identity configuration

Configure these non-secret values through reviewed deployment configuration:

```text
NETWATCH_OIDC_ENABLED=true
NETWATCH_OIDC_ISSUER=https://identity.example.com/tenant
NETWATCH_OIDC_AUDIENCE=netwatch-production
NETWATCH_OIDC_JWKS_URL=https://identity.example.com/tenant/keys
NETWATCH_OIDC_GROUPS_CLAIM=groups
NETWATCH_OIDC_ADMIN_GROUPS=netwatch-admins
NETWATCH_OIDC_OPERATOR_GROUPS=netwatch-operators
NETWATCH_OIDC_VIEWER_GROUPS=netwatch-viewers
NETWATCH_OIDC_ALGORITHMS=RS256
NETWATCH_OIDC_MAX_TOKEN_AGE_SECONDS=3600
```

Use dedicated NetWatch groups. Do not map a broad organization-wide group to Admin or Operator. Group matching is exact, and configuration fails if the same group is mapped to more than one role. Rotate IdP signing keys through the JWKS endpoint; NetWatch caches the bounded JWKS set but does not keep a separate signing-key cache that can outlive that set.

If a bearer token is present but invalid, NetWatch rejects it and never falls back to a simultaneously supplied shared key. If OIDC is enabled with incomplete or non-HTTPS settings, readiness fails closed.

## Server-only secrets

Inject secrets from the platform's managed secret store at runtime:

- `NETWATCH_AUDIT_HMAC_KEY`: independent 32+ character value, backed up separately from SQLite.
- `OPENAI_API_KEY`: optional provider project key.
- `NETWATCH_AI_SAFETY_SECRET`: optional independent AI pseudonymization key.
- `NETWATCH_AI_SUBJECT_ID`: optional opaque deployment subject.
- `NETWATCH_API_KEY`, `NETWATCH_OPERATOR_KEY`, `NETWATCH_VIEWER_KEY`: optional break-glass role keys.

The staged backend settings are explicit and fail closed:

- `NETWATCH_ENTERPRISE_MODE`: `single_tenant` (safe default), `compatibility` (durable local outbox/jobs), or `shared_service` (not ready until external adapters and migrations are validated).
- `NETWATCH_DATABASE_BACKEND`, `NETWATCH_COORDINATION_BACKEND`, `NETWATCH_OBJECT_STORAGE_BACKEND`, and `NETWATCH_EVENT_SINK`: backend selections; do not select shared-service values until the matching adapters are deployed and tested.

Do not put these values in Git, a ConfigMap, image layer, frontend setting, ticket, report, or screenshot. Each enabled role key must be unique. The audit HMAC key must not equal a role key, provider key, or AI safety secret; NetWatch readiness fails when that separation is violated.

Treat the audit HMAC key as long-lived integrity material under the organization's managed-key lifecycle. Replacing it while protected rows remain makes verification fail closed. Restore the previous key to recover verification; before any planned audit-chain reinitialization, export and archive the existing evidence in approved append-only storage. NetWatch intentionally has no remote endpoint that resets or re-signs the chain.

## Audit and correlation

New protected events contain an individual actor ID, role, authentication method, generated request ID, operation, target, outcome, and bounded summary. NetWatch chains them with HMAC-SHA256 using `NETWATCH_AUDIT_HMAC_KEY`.

Admins can check `/api/audit-log/integrity`. Verification covers every retained protected row plus a keyed head checkpoint, detecting changed content, broken links, an unprotected suffix, or deletion of the latest protected rows. Readiness and privileged operations use the same full-chain check. Retention pruning preserves a verifiable retained segment, but intentionally removed history requires centralized append-only export for full-lifetime evidence. Pre-v1.6 rows remain `Legacy`; a local database attacker who also obtains the HMAC key is outside this control.

Every response includes `X-Request-ID`. Application logs record only request ID, method, route template, status, and duration; bearer tokens, shared keys, query strings, private path values, and request bodies are excluded.

## Health and monitoring

- `/api/health/live`: process liveness only; never depends on the database or IdP.
- `/api/health/ready`: local database, unique role-key configuration, OIDC configuration, and a full retained audit-chain result cached for no more than five seconds. Privileged operations always force a fresh verification.
- `/api/metrics`: authenticated, low-cardinality Prometheus text without target/IP labels.
- `/api/enterprise/status`: Admin-only non-secret capability, readiness, outbox, and job status; it never returns backend credentials or URLs.

Alert on readiness failures, HTTP 5xx growth, overdue/critical unresolved cases, scheduler failure logs, and backup age. Do not use the liveness probe as an external dependency check; repeated restarts during an IdP or storage incident can make an outage worse.

## Kubernetes template

`deploy/kubernetes.yaml` provides the hardened single-tenant starting point with:

For repeatable cluster application, `deploy/kustomization-single-tenant.yaml` pins the deployment to one replica and `Recreate` updates, preserving the SQLite one-active-instance boundary.

- one replica and `Recreate` updates for the current SQLite boundary;
- non-root execution, read-only root filesystem, no privilege escalation, runtime-default seccomp, and only `NET_RAW` added for approved ICMP checks and bounded packet-header capture;
- disabled service-account token mounting;
- CPU/memory requests and limits;
- liveness/readiness probes;
- a cluster-internal Service and persistent volume;
- secret and ConfigMap references without embedded credentials.

Replace the image, host/origin, issuer, audience, JWKS URL, groups, StorageClass, and namespace policy before applying it. Put an approved identity-aware TLS gateway in front of the ClusterIP Service; do not expose the pod directly to the Internet. Validate that the cluster network policy and CNI permit only the approved private scan ranges and required HTTPS/DNS egress.

`deploy/kubernetes-enterprise.yaml` is an ABC shared-service **reference manifest**, not a production approval or deployable-as-is package. It describes two stateless API replicas, a rolling update, a PodDisruptionBudget, default-deny network policy, managed secret references, and PostgreSQL/Redis/S3/event-sink configuration. Build it with `Dockerfile.enterprise`, which installs only optional adapter dependencies into a separate image. Before applying it, replace the image with a signed digest, create managed secrets, and complete adapter, migration, tenant-scope, resource, failure-injection, and recovery validation.

A supply-chain release workflow is a required follow-up control: it should produce an SPDX SBOM, build signed images with provenance, and verify attestations before cluster admission. The current repository does not claim that this workflow is installed; adding workflow files requires GitHub credentials with the `workflows` permission.

## Rollout and recovery

1. Back up SQLite through the Admin snapshot endpoint and validate the copy in staging with `python3 scripts/verify_sqlite_backup.py <backup> --expected-schema 10`. This utility is read-only and does not restore over a live database.
2. Create managed secrets and reviewed non-secret configuration.
3. Configure IdP application/audience and least-privilege groups.
4. Deploy to staging behind the identity gateway.
5. Test Viewer, Operator, Admin, unmapped, expired-token, wrong-audience, and break-glass paths.
6. Verify `/api/health/ready`, Prometheus scraping, request correlation, and audit-chain status.
7. Run a bounded approved scan and capture on a staging sensor interface; verify device identity, no-payload behavior, policy, maintenance, case, report, backup, and optional AI workflows.
8. Complete the organization's security, privacy, data-retention, AI, and disaster-recovery reviews before production.
9. Verify the release image digest, SBOM, provenance attestation, dependency policy, and migration checksum before production promotion. The current repository does not claim that its SBOM/provenance workflow is installed.
10. Run `python3 scripts/benchmark_api.py` against staging for health, inventory, report, and retention-preview endpoints. Record p50/p95/p99, throughput, errors, CPU/memory, database connections, and queue age; do not use the harness to start broad network scans automatically.
11. Complete the [security assessment checklist](security-assessment-checklist.md) and attach staging/manual evidence before a production readiness review.

## Current scale boundary

The current release is appropriate for one active application instance per database. Do not run multiple replicas against copied or shared SQLite files. The scheduler, request rate limits, scan semaphore, and some metrics are process-local. Compatibility mode adds durable outbox/jobs and explicit readiness reporting, but does not make SQLite active-active.

True multi-replica HA requires a future architecture with a transactional shared database such as PostgreSQL, distributed rate/quota state, external job workers with leader election, object storage or managed backup, centralized append-only audit export, tenant/resource policy enforcement, and tested zero/low-downtime migrations. The current migration advances SQLite schema tracking to version 10 and preserves existing data.
 Until then, use platform restart/recreate recovery, persistent storage, monitored readiness, encrypted off-host backups, and a documented recovery-time objective.
