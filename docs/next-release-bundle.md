# NetWatch Next Release Bundle

## Scope

This release prioritizes high-value improvements for a larger internal operations team without changing NetWatch's defensive network scope. It focuses on evidence presentation, governance, and safe lifecycle operations rather than adding broader scanning capabilities.

| Capability | Operator value | Safety boundary |
|---|---|---|
| PDF report export | Gives security and operations teams a portable executive/hand-off artifact alongside Markdown and HTML | Uses the same redacted report inputs; no secrets, payloads, or raw provider material |
| Retention governance | Makes data lifecycle visible and gives Admins a dry-run-first cleanup workflow | Audit-chain rows are not deleted by the cleanup endpoint; destructive cleanup requires an explicit Admin confirmation and audit record |
| Retention status | Shows current row counts, oldest/newest timestamps, configured limits, and cleanup eligibility | Returns aggregate counts and timestamps only, not private target payloads |
| Operator UX | Makes report and retention state discoverable from the existing Operations surface | Uses same-origin authenticated API calls and existing server-side role checks |
| Documentation and runbook | Makes release behavior, restore implications, and approval steps clear for a larger team | Does not claim regulatory compliance or automatic HA |

## Non-goals

This release does not enable active-active SQLite, unrestricted network discovery, packet payload retention, automatic case closure, or autonomous remediation. Multi-instance deployment still requires the enterprise shared-service prerequisites documented in the ABC architecture.

## Rollout contract

The release remains compatible with the current SQLite schema and adds only bounded, explicitly audited lifecycle operations. PDF rendering is optional at runtime; if the PDF dependency is unavailable, the existing Markdown and HTML report routes remain available and the API returns a safe service-unavailable response for PDF only.
