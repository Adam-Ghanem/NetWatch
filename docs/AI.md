# NetWatch AI — OpenAI and Anthropic (BYOK)

NetWatch Intelligence is optional. Inventory, authorized network scans, traffic
analysis and the local Risk Advisor do not require any external AI key.

## Configure a provider

Choose **one** AI provider for each NetWatch instance. Set variables in the
server-side `.env` or a managed secret, **never** in frontend code or Git.

| Setting | OpenAI / GPT | Anthropic / Claude |
| --- | --- | --- |
| `NETWATCH_AI_PROVIDER` | `openai` | `anthropic` |
| Key | `OPENAI_API_KEY` | `ANTHROPIC_API_KEY` |
| Default model | `gpt-5-mini` | `claude-sonnet-5-5` |

OpenAI:

```dotenv
NETWATCH_AI_PROVIDER=openai
OPENAI_API_KEY=<real-openai-api-key>
NETWATCH_AI_MODEL=gpt-5-mini
```

Claude:

```dotenv
NETWATCH_AI_PROVIDER=anthropic
ANTHROPIC_API_KEY=<real-anthropic-api-key>
NETWATCH_AI_MODEL=claude-sonnet-5-5
```

Use your own valid provider-issued credentials. Paid chat subscriptions are not
the same as API access. In Docker Compose restart with
`docker compose up -d --build netwatch`. For Kubernetes use managed secrets.
The selected provider and model are visible via authenticated
`/api/intelligence/status`; the key is not.

**No implicit fallback.** Missing Claude credentials never cause a request to
OpenAI, even if OpenAI credentials are available. Unknown provider values fail
closed. Existing OpenAI installations continue to use OpenAI by default.

## Privacy, safety and costs

- Provider keys are server-side, included only in HTTPS authentication headers,
  and must never appear in generated logs, reports, browser URLs or UI.
- Both models receive the same fixed defensive instructions with only an
  aggregated, de-identified operational snapshot (no raw IP, CIDR, hostname,
  owner, notes or packet content).
- Both use structured JSON output and server-side Pydantic validation. Invalid,
  refused, incomplete or oversized responses fail closed.
- No provider has network scan, shell or remediation tools.
- The app enforces rate/concurrency/time limits, daily AI budgets and
  provider/model-specific caching. Configure spend/rate caps at the provider.
- OpenAI Responses uses `store=false`; Claude Messages uses structured output.
  Check the chosen provider's privacy and retention terms separately before
  enabling external AI on company networks.
- Failed/disabled AI does not interrupt core monitoring and the local Risk Advisor.

## Continuous evidence-only analysis (opt-in)

NetWatch can periodically use the selected GPT or Claude provider to analyze
**already-collected, aggregated, de-identified** inventory/service/case
evidence. This does **not** schedule scans or transmit raw private network
data. Unlike the ChatGPT GitHub-upgrade automation, this scheduler runs only
inside your deployed NetWatch server.

The default is **disabled** and no provider calls occur without an explicit
server-side opt-in. To enable, in server-side `.env`:

```dotenv
NETWATCH_AI_ENABLED=true
NETWATCH_AI_AUTO_ANALYSIS_ENABLED=true
NETWATCH_AI_AUTO_INTERVAL_SECONDS=3600
```

Intervals are clamped between one and 24 hours. The scheduler runs only in
the supported single-instance/compatibility deployment modes; it never
activates the unvalidated shared-service or multi-replica architecture.
The first cycle runs when the application starts, then at each interval.
A durable SQLite claim prevents duplicate requests within the configured
interval, including after restart. **Unchanged evidence previously analyzed
successfully is skipped**; failures are eligible for retry only after the
interval. This prevents sending periodic duplicate provider requests just
to generate activity.

Every actual provider request still passes the existing key separation,
audit-integrity gate, bounded concurrency, rate limits, daily request
budget, redacted fixed prompt, schema validation, and cached brief storage.
AI never chooses scan targets, runs commands, or remediates findings.
If a provider is unavailable or rate limited, local monitoring continues.

An Admin can inspect aggregate scheduler status (no evidence hashes or
keys) through `GET /api/intelligence/auto/status`; look at
`last_attempt_at`, `last_success_at`, and `last_outcome`.
This is advisory automation, **not** an enterprise distributed scheduler.
Before connecting real company evidence to external APIs, complete your
organization's data-processing/privacy approval and provider spend controls.

## Verify

Run `pytest -q tests/test_ai_advisor.py tests/test_ai_anthropic.py
tests/test_api.py` for mocked provider, privacy, auth and cache checks.
A staging test with an actual key is still required for production approval.
