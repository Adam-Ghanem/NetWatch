# NetWatch Risk Advisor

The Risk Advisor is a local analysis layer inside NetWatch.

It reads the current dashboard data and generates a defensive summary:

- Overall risk level
- Short explanation of the latest results
- Priority findings
- Suggested next steps
- Confidence level
- Exportable Markdown notes

## Important note

The deterministic Risk Advisor does not send scan results to an external service. It is local project logic built from the data already shown in the app and remains available without a provider key.

## Optional NetWatch Intelligence

NetWatch v1.5 adds an explicitly requested second-review path beside the local advisor. The browser never talks to the provider and never receives `OPENAI_API_KEY`. The backend builds a bounded snapshot containing aggregate counts, known common-service exposure, de-identified case references, and operational state. It excludes IP addresses, CIDRs, hostnames, owners, departments, locations, notes, raw event details, prompts, and secrets.

The provider contract:

- Uses the Responses API with response storage disabled
- Uses a fixed defensive instruction and strict JSON schema
- Accepts no arbitrary end-user prompt
- Exposes no tools, scan functions, credentials, or mutation capability
- Requires evidence limitations and human validation
- Applies a stable opaque safety identifier derived from an independent server secret and random deployment subject, never from the provider key, role, username, hostname, or client address
- Refuses provider redirects and reserves the atomic UTC daily budget before each outbound call
- Fails closed on malformed, refused, oversized, timed-out, or unavailable responses

Successful briefs are cached locally for a bounded period. Call metadata and safe error codes are retained in the bounded `intelligence_events` table; the full snapshot and prompt are not stored. Separate rate, concurrency, daily-request, timeout, and output limits reduce abuse and unexpected cost. These controls do not replace provider project spend limits or organizational identity controls.

This design keeps the project easy to run in a lab or company demo without API keys or Internet access.

## Input data

The advisor uses:

- Latest Network Scan table
- Latest Port Audit table
- SQLite asset inventory

## Output

The advisor shows:

- Risk level
- Confidence level
- Inventory count
- Advisor summary
- Priority findings
- Suggested next steps

It can also export the notes as:

```text
netwatch_advisor_notes.md
```

## Limits

The advisor is not a full security audit. It is a local decision-support component that helps decide what to review first.

For company production use, it can later be extended with approved scan ranges, company policy mapping, PDF executive reports, and report approval workflow.
