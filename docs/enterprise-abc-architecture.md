# NetWatch ABC Enterprise Architecture

## Purpose

This document defines the staged path from the current trusted single-instance deployment to a large-company operating model. It is intentionally cloud-neutral, with Kubernetes and Google Cloud-compatible deployment examples. It does not claim that NetWatch is automatically compliant with Google, SOC 2, ISO 27001, or any other organization or framework.

## Stages

| Stage | Operating model | Primary outcome | Safe boundary |
|---|---|---|---|
| **C: Compatibility-first** | SQLite remains the default local backend; storage, job, event, and object interfaces are explicit; PostgreSQL, Redis, and object-storage adapters are introduced behind configuration and contract tests | Existing users keep working while enterprise seams become testable | Enterprise adapters are disabled until their readiness checks and migration tests pass |
| **A: Enterprise shared service** | Multiple stateless API replicas; transactional PostgreSQL; distributed queue/lease state; isolated sensor workers; object storage; centralized audit export; central identity and observability | Multi-site, multi-team, active-active operation with controlled scaling | Network scans remain authorization-first and bounded; workers cannot choose arbitrary targets |
| **B: Hardened single tenant** | One active instance with strong container/Kubernetes hardening, immutable releases, backup/restore drills, SLOs, and centralized export | Defensible business-unit deployment when shared services are not yet available | The deployment remains explicitly single-instance and must not be scaled horizontally against SQLite |

## Target default

The implementation proceeds in the order **C → A**, while keeping **B** as a maintained fallback profile. The enterprise target is a Kubernetes deployment that can run on a managed platform such as Google Kubernetes Engine or an equivalent on-premises cluster. The application remains cloud-neutral: PostgreSQL-compatible storage, Redis-compatible coordination, S3-compatible object storage, OIDC identity, Prometheus/OpenTelemetry observability, and a pluggable event sink are the portability seams.

## Non-negotiable controls

NetWatch must preserve explicit authorization before network actions, server-side role/resource checks, bounded scan and capture limits, no-payload traffic handling, de-identified outbound notifications, and human review of advisory output. Multi-tenancy must be deny-by-default: every organization, site, sensor, policy, job, alert, and evidence query receives a tenant/resource scope before execution.

Secrets stay in managed runtime secret storage. Database migrations are forward-only, reviewed, and backward-compatible for at least one rollout window. Every asynchronous job is idempotent, carries a correlation ID, has a bounded retry policy, and records terminal failure. Every privileged mutation produces audit evidence that can be exported to an append-only destination.

## Migration sequence

1. Introduce repository and connection interfaces while retaining SQLite behavior and tests.
2. Add a transactional outbox and durable job model to SQLite, then implement the same contracts for PostgreSQL/Redis adapters.
3. Add tenant/resource policy primitives and make the current single-tenant deployment use a default organization scope.
4. Add worker and lease abstractions, then move scheduler and notification dispatch behind them.
5. Add object-storage backup/export adapters and centralized audit/event sinks.
6. Add active-active Kubernetes manifests, PodDisruptionBudgets, network policies, migration jobs, and rollout/rollback runbooks.
7. Enable enterprise backends only after contract, migration, failure-injection, security, and recovery tests pass.

## References

[1]: https://www.nist.gov/publications/zero-trust-architecture "NIST Zero Trust Architecture"
[2]: https://slsa.dev/ "SLSA Supply-chain Levels for Software Artifacts"
[3]: https://sre.google/sre-book/service-level-objectives/ "Google SRE: Service Level Objectives"
