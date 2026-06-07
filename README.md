# NetWatch

![NetWatch Banner](assets/netwatch-banner-v2.svg)

NetWatch is a local network monitoring dashboard built with Python and Streamlit.

I made it as a practical cybersecurity/networking portfolio project. It is not a hacking tool; it is an admin-style dashboard for checking a local network, seeing which hosts respond, reviewing a short list of common services, saving a local inventory, and exporting reports.

> Use it only on networks you own or where you have clear permission.

## Company-ready documentation added

The repository includes handover and deployment material so the project can be reviewed more easily by a company or internship supervisor:

- `docs/company-handover.md`
- `docs/demo-script.md`
- `docs/deployment.md`
- `docs/security-review.md`
- `docs/acceptance-checklist.md`
- `docs/architecture.md`
- `docker-compose.yml`
- GitHub issue templates

## What changed in v0.3.1

- Added Docker Compose deployment file
- Added company handover notes
- Added demo presentation script
- Added acceptance checklist
- Added security review notes
- Added bug report and feature request templates

## Main features

- Ping one private/local IP address
- Scan a local CIDR range such as `192.168.1.0/24`
- Audit common TCP ports such as SSH, HTTP, HTTPS, SMB, MySQL, RDP and PostgreSQL
- Block public Internet targets from the app
- Save local assets and last-seen data in SQLite
- Show exposure score, level and top recommendations
- Export hosts, ports and inventory as CSV
- Generate Markdown and HTML reports
- Keep a local history of checks

## Pages

- **Overview**: latest metrics, risk chart and recent saved runs
- **Network Scan**: checks which local hosts respond
- **Host Check**: tests one IP address
- **Port Audit**: checks common services and shows recommendations
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
- SQLite storage
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
├── app.py
├── config.py
├── history_store.py
├── inventory_store.py
├── logger.py
├── network_scanner.py
├── network_tools.py
├── ping_checker.py
├── port_scanner.py
├── report_builder.py
├── risk_engine.py
├── security.py
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
│   ├── architecture.md
│   ├── company-handover.md
│   ├── demo-script.md
│   ├── deployment.md
│   ├── run-on-kali.md
│   └── security-review.md
└── tests/
    ├── test_network_tools.py
    ├── test_report_builder.py
    ├── test_risk_engine.py
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

## Tests

```bash
pytest -q
```

## Next improvements

- Add PDF export after the HTML report
- Add screenshots from a real lab run
- Add device names/vendor lookup for local networks
- Add optional authentication for shared deployments
- Add a small SQLite cleanup/export tool

## Disclaimer

This project is for learning and authorized defensive testing only. Do not check networks or devices without permission.
