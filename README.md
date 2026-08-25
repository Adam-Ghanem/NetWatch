<p align="center">
  <img src="frontend/assets/netwatch-logo.svg" alt="NetWatch" width="180">
</p>

<h1 align="center">NetWatch</h1>

<p align="center">
  <strong>Local-first network visibility for authorized environments.</strong><br>
  Discover assets. Understand changes. Investigate with evidence.
</p>

<p align="center">
  <a href="https://github.com/Adam-Ghanem/NetWatch/actions/workflows/python-ci.yml"><img src="https://github.com/Adam-Ghanem/NetWatch/actions/workflows/python-ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/License-MIT-2c0f50.svg" alt="MIT License">
</p>

> **NetWatch is a defensive tool.** Use it only on networks and devices you own or are explicitly authorized to assess.

## What is NetWatch?

NetWatch is a self-hosted network visibility platform for homelabs, IT teams, and small security operations.

It combines:

- **Asset discovery** — find and track devices on an authorized local network.
- **Device intelligence** — collect evidence for hostname, MAC/OUI, device family, and OS hints.
- **Change detection** — see what appeared, disappeared, or changed between observations.
- **Service review** — inspect common TCP exposure without pretending an open port is a vulnerability.
- **Evidence & history** — keep observations, ownership, criticality, and investigation context together.
- **AI investigation** — optionally use an LLM to reason over NetWatch evidence with the user's own API key.

NetWatch is intentionally **local-first**. Your network inventory does not need to be uploaded to a third-party SaaS just to use the core product.

## Why it exists

Network tools often answer **"what is there?"** and security platforms often answer **"what is risky?"**.

NetWatch focuses on the space between them:

```text
Authorized network
       │
       ▼
    Discovery
       │
       ▼
   Evidence + identity
       │
       ▼
 Change detection ── Service review
       │
       ▼
 Investigation context
       │
       ▼
 Optional AI analysis
```

The goal is simple: **make network changes understandable without turning the tool into an offensive scanner.**

## Screenshots

The previews below use sample data and do not contain real network identifiers.

<p align="center">
  <img src="docs/screenshots/overview.svg" alt="NetWatch overview dashboard" width="96%">
</p>

<p align="center"><strong>Overview</strong></p>

<p align="center">
  <img src="docs/screenshots/port-audit.svg" alt="NetWatch port audit preview" width="96%">
</p>

<p align="center"><strong>Port audit</strong></p>

<p align="center">
  <img src="docs/screenshots/risk-advisor.svg" alt="NetWatch risk advisor preview" width="96%">
</p>

<p align="center"><strong>Risk advisor</strong></p>

## AI

AI is optional. NetWatch does not ship with a shared API key.

If you enable AI, **you provide your own provider key** through the server environment:

```bash
export OPENAI_API_KEY="your-key"
export NETWATCH_AI_MODEL="gpt-5-mini"
```

The AI layer can analyze collected NetWatch evidence and use explicitly registered evidence tools. It is designed to stay evidence-bound: it should not invent observations or perform offensive actions.

No API key is required to use the core discovery and monitoring features.

## Quick start

Requirements: **Git, Python 3.10+, Docker, and Docker Compose.**

```bash
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
python scripts/start.py
```

Then open:

```text
http://127.0.0.1:8000
```

For a manual deployment:

```bash
cp .env.example .env
docker compose up -d --build netwatch
```

## Security principles

NetWatch follows a few hard rules:

- Authorization comes before scanning.
- Evidence is preferred over guesses.
- Unknown stays unknown when confidence is insufficient.
- The core product works without AI.
- AI credentials belong to the user, not the repository.
- AI tools are explicitly registered and bounded.
- Network actions are defensive and scope-controlled.
- Secrets should never be committed to Git.

## Project status

NetWatch is an actively developed project. Features are evolving, and deployment/security guarantees should be validated in your own environment before production use.

For architecture and implementation details, see the `docs/` directory.

## Contributing

Issues, bug reports, tests, documentation, and focused features are welcome.

Please keep contributions aligned with NetWatch's core idea: **local-first, evidence-driven, authorized network visibility.**

## License

MIT — see [`LICENSE`](LICENSE).
