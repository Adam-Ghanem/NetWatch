# NetWatch

![NetWatch Banner](assets/netwatch-banner-v2.svg)

NetWatch is a local network monitoring dashboard built with Python and Streamlit.

I made it as a practical cybersecurity/networking portfolio project. It is not a hacking tool; it is an admin-style dashboard for checking a local network, seeing which hosts respond, reviewing a short list of common services, saving a local inventory, exporting reports, and generating local AI-style advice.

> Use it only on networks you own or where you have clear permission.

## What changed in v0.5.0

This version adds an integrated **AI Advisor**:

- New **AI Advisor** page in the Streamlit sidebar
- Local AI-style summary of scan results
- Risk level explanation
- Priority findings generated from the latest Port Audit
- Suggested next steps for the technical team
- Confidence level based on available data
- Markdown export: `netwatch_ai_advice.md`
- No external API calls and no API key required

## What changed in v0.4.0

This version focuses on more precise information:

- Host profiling with latency in milliseconds
- TTL extraction from ping replies
- Basic OS hint from TTL value
- Reverse DNS hostname lookup when available
- Detailed port output with protocol and response time
- Service descriptions and common role hints
- Device role hint based on observed open services
- Extra tests for host parsing and service catalog logic

## Company-ready documentation added

The repository includes handover and deployment material so the project can be reviewed more easily by a company or internship supervisor:

- `docs/company-handover.md`
- `docs/demo-script.md`
- `docs/deployment.md`
- `docs/security-review.md`
- `docs/acceptance-checklist.md`
- `docs/architecture.md`
- `docs/ai-advisor.md`
- `docker-compose.yml`
- GitHub issue templates

## Main features

- Ping one private/local IP address
- Show latency, TTL, hostname and OS hint for host checks
- Scan a local CIDR range such as `192.168.1.0/24`
- Audit common TCP ports such as SSH, HTTP, HTTPS, SMB, MySQL, RDP and PostgreSQL
- Show service description, common role, response time and device role hint
- Use AI Advisor to summarize risk and next actions
- Block public Internet targets from the app
- Save local assets and last-seen data in SQLite
- Show exposure score, level and top recommendations
- Export hosts, ports, inventory and AI advice
- Generate Markdown and HTML reports
- Keep a local history of checks

## Accuracy notes

NetWatch gives local visibility, not absolute truth:

- Latency and TTL depend on ICMP replies.
- Hostname depends on reverse DNS availability.
- Device role is a hint based on open ports, not guaranteed identification.
- Firewalls can make services appear closed or filtered.
- The AI Advisor is local and rule-based; it helps explain results but does not replace a full security audit.
- The port list is intentionally short and defensive.

## Pages

- **Overview**: latest metrics, risk chart and recent saved runs
- **Network Scan**: checks which local hosts respond
- **Host Check**: tests one IP address and shows profile details
- **Port Audit**: checks common services and shows detailed recommendations
- **AI Advisor**: summarizes results, priorities and next steps
- **Inventory**: saved local assets from previous checks
- **Network Tools**: quick CIDR/subnet helper
- **Reports**: Markdown and HTML report export
- **Safety**: project limits and allowed use cases

## Why I built it

I wanted a project related to what I study: networks, security basics, and Python. NetWatch helped me practice:

- Python modules and clean file structure
- Streamlit interface design
- IP and CIDR validation
- Socket basics
- Ping output parsing
- Service catalog mapping
- SQLite storage
- Local AI-style advisory logic
- CSV/Markdown/HTML report generation
- Defensive security thinking
- GitHub project organization

## Tech stack

- Python
- Streamlit
- Pandas
- Plotly
- SQLite
- Pytest
- GitHub Actions
- Docker

## Project structure

```text
NetWatch/
├── ai_advisor.py
├── app.py
├── config.py
├── history_store.py
├── host_profiler.py
├── inventory_store.py
├── logger.py
├── network_scanner.py
├── network_tools.py
├── ping_checker.py
├── port_scanner.py
├── report_builder.py
├── risk_engine.py
├── security.py
├── service_catalog.py
├── requirements.txt
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── assets/
│   └── netwatch-banner-v2.svg
├── data/
│   └── sample_hosts.csv
├── docs/
│   ├── acceptance-checklist.md
│   ├── ai-advisor.md
│   ├── architecture.md
│   ├── company-handover.md
│   ├── demo-script.md
│   ├── deployment.md
│   ├── run-on-kali.md
│   └── security-review.md
└── tests/
    ├── test_ai_advisor.py
    ├── test_host_profiler.py
    ├── test_network_tools.py
    ├── test_report_builder.py
    ├── test_risk_engine.py
    ├── test_service_catalog.py
    └── test_security.py
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it.

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the app:

```bash
streamlit run app.py
```

Open the local URL shown by Streamlit, usually:

```text
http://localhost:8501
```

## Kali / fish shell quick run

```fish
python3 -m venv venv
source venv/bin/activate.fish
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m streamlit run app.py
```

## Docker

```bash
docker build -t netwatch .
docker run -p 8501:8501 netwatch
```

## Docker Compose

```bash
docker compose up -d --build
```

## Safety notes

NetWatch is intentionally limited:

- It only accepts private/local IP ranges.
- It limits the number of hosts in one scan.
- It checks a short list of common ports only.
- It does not include exploitation, brute force, password attacks, stealth, or evasion.
- The recommendations are basic and defensive.
- The AI Advisor uses local project data and does not send results outside the machine.

## Tests

```bash
pytest -q
```

## Next improvements

- Add PDF export after the HTML report
- Add screenshots from a real lab run
- Add optional authentication for shared deployments
- Add a small SQLite cleanup/export tool
- Add manually editable asset owner/location fields
- Add optional external LLM integration for private company deployments

## Disclaimer

This project is for learning and authorized defensive testing only. Do not check networks or devices without permission.
