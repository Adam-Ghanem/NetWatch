# NetWatch AI

NetWatch can optionally use a real OpenAI model for defensive analysis.

## Configuration

Set the user's own API key in the runtime environment:

```bash
export OPENAI_API_KEY="..."
export NETWATCH_AI_MODEL="gpt-5-mini"
```

Never commit the key to the repository, logs, configuration files, or client-side code.

The integration uses the OpenAI Responses API and sends only the supplied NetWatch asset/findings context. If `OPENAI_API_KEY` is absent, the AI integration remains disabled; core NetWatch functionality does not require the key.

The model is instructed to stay evidence-bound and provide defensive analysis. AI output is advisory and must not be treated as authoritative vulnerability confirmation.
