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

## Verify

Run `pytest -q tests/test_ai_advisor.py tests/test_ai_anthropic.py
tests/test_api.py` for mocked provider, privacy, auth and cache checks.
A staging test with an actual key is still required for production approval.
