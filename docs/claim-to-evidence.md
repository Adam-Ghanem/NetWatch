# Claim-to-Evidence Matrix

This matrix prevents documentation from overstating the current readiness of NetWatch. A claim is considered current only when the repository or a recorded deployment test provides direct evidence.

| Claim | Status | Evidence or required proof |
|---|---|---|
| Role-based API access and server-side authorization exist | **Verified in repository** | API role-isolation tests, authentication tests, and Security CI. |
| Network operations are authorization-first and bounded | **Verified in repository** | CIDR/target validation, scan/capture limits, authorization tests, and traffic metadata tests. |
| Traffic capture is metadata-only and does not retain payloads | **Verified in repository** | Capture implementation, response contract, retention tests, and acceptance checklist. |
| Audit events are integrity-protected and request-correlated | **Verified in repository** | HMAC-chain tests, request-ID tests, integrity readiness checks, and audit API tests. |
| Device names/hostnames/MAC evidence appear after authorized scans | **Verified in repository** | Scan identity tests, frontend syntax checks, and merged scan-identity PR. |
| PDF/Markdown/HTML reports are available with bounded/redacted inputs | **Verified in repository** | Report API tests, PDF signature test, report-builder tests, and acceptance checklist. |
| Retention preview and confirmed cleanup are Admin-only and preserve audit evidence | **Verified in repository** | Retention store/API tests and explicit destructive confirmation guard. |
| SQLite is safe for one active instance under the documented boundary | **Conditionally verified** | Single-instance deployment guide, Kustomize fallback, tests, and operational runbook. Validate again in the target environment. |
| NetWatch is multi-tenant production-ready | **Not verified; roadmap** | Requires PostgreSQL migration, tenant context, negative isolation tests, policy enforcement, and staging evidence. |
| NetWatch is active-active multi-replica production-ready | **Not verified; roadmap** | Requires external workers, distributed quotas, shared storage, failure-injection, migration, and recovery evidence. |
| Kubernetes reference is production-ready as-is | **False; reference only** | The manifest requires signed image, managed secrets, completed adapters, resource profiles, tenant controls, staging rollout, and recovery validation. |
| SBOM/provenance attestations are enforced in GitHub CI | **Not verified; follow-up** | Workflow files require a GitHub credential with `workflows` permission, plus release verification. |
| SOC 2, ISO 27001, Google, or other compliance approval exists | **False** | NetWatch provides technical controls only; organizational review and independent evidence are required. |

## Review rule

Before each release, maintainers must update this matrix and attach the corresponding test, staging record, benchmark, security retest, or recovery evidence. Unverified claims must remain labeled `roadmap`, `reference`, `conditional`, or `not approved`.
