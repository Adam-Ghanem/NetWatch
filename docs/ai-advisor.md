# NetWatch AI Advisor

The AI Advisor is a local analysis layer inside NetWatch.

It reads the current dashboard data and generates a simple defensive summary:

- Overall risk level
- Short explanation of the latest results
- Priority findings
- Suggested next steps
- Confidence level
- Exportable Markdown advice

## Important note

The AI Advisor does not send scan results to an external API. It is a deterministic local advisor built from the data already shown in the app.

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

It can also export the advice as:

```text
netwatch_ai_advice.md
```

## Limits

The advisor is not a full security audit. It is a local assistant that helps explain the results and decide what to review first.

For company production use, it can later be extended with:

- Approved scan ranges
- Company policy mapping
- PDF executive reports
- Optional external LLM integration
- Human approval workflow before sharing reports
