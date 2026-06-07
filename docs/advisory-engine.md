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

The Risk Advisor does not send scan results to an external service. It is deterministic local project logic built from the data already shown in the app.

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
