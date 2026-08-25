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

NetWatch is a self-hosted network visibility platform for authorized networks.

- Asset discovery
- Device / OS intelligence
- Change detection
- Service review
- Evidence & history
- Optional AI investigation with your own API key

## Screenshots

<p align="center">
  <img src="docs/screenshots/overview.svg" alt="NetWatch overview dashboard" width="96%">
</p>

<p align="center"><strong>Overview</strong></p>

<table align="center">
<tr>
<td width="50%" align="center"><img src="docs/screenshots/risk-advisor.svg" alt="NetWatch risk advisor" width="100%"><br><strong>Risk Advisor</strong></td>
<td width="50%" align="center"><img src="docs/screenshots/port-audit.svg" alt="NetWatch port audit" width="100%"><br><strong>Port Audit</strong></td>
</tr>
</table>

## AI

Optional. Use your own provider key:

```bash
export OPENAI_API_KEY="your-key"
export NETWATCH_AI_MODEL="gpt-5-mini"
```

AI analyzes NetWatch evidence through explicitly registered tools. No API key is required for core features.

## Quick Start

```bash
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
python scripts/start.py
```

Open `http://127.0.0.1:8000`.

## Security

Authorization-first, evidence-driven, scope-controlled, and local-first. Never commit secrets or use NetWatch against systems you are not authorized to assess.

## License

MIT — see [`LICENSE`](LICENSE).
