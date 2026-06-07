# NetWatch

![NetWatch Banner](assets/netwatch-banner-v2.svg)

NetWatch is a small local network monitoring dashboard built with Python and Streamlit.

I made it as a practical cybersecurity/networking portfolio project. It is not a hacking tool; it is a simple admin-style dashboard for checking a local network, seeing which hosts respond, checking a short list of common ports, and exporting a basic report.

> Use it only on networks you own or where you have clear permission.

## What changed in v0.2.0

- New dark dashboard design
- Overview page with cards and charts
- Separate pages for network scan, host check, port audit, reports, and safety notes
- Local scan history saved to `data/scan_history.csv`
- Markdown report download from the latest results
- Cleaner banner and Streamlit theme
- Extra tests for report summary logic

## Main features

- Ping one private/local IP address
- Scan a local CIDR range such as `192.168.1.0/24`
- Audit common TCP ports such as SSH, HTTP, HTTPS, SMB, MySQL, RDP, PostgreSQL
- Block public Internet targets from the app
- Show basic risk levels and simple hardening advice
- Export hosts and port results as CSV
- Generate a Markdown report
- Keep a local history of scans

## Why I built it

I wanted a project related to what I study: networks, security basics, and Python. NetWatch helped me practice:

- Python modules and clean file structure
- Streamlit interface design
- IP and CIDR validation
- Socket basics
- Defensive security thinking
- CSV/report generation
- GitHub project organization

## Tech stack

- Python
- Streamlit
- Pandas
- Plotly
- Pytest
- GitHub Actions
- Docker

## Project structure

```text
NetWatch/
├── app.py
├── config.py
├── history_store.py
├── logger.py
├── network_scanner.py
├── ping_checker.py
├── port_scanner.py
├── report_builder.py
├── security.py
├── requirements.txt
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── Dockerfile
├── Makefile
├── assets/
│   └── netwatch-banner-v2.svg
├── data/
│   └── sample_hosts.csv
└── tests/
    ├── test_report_builder.py
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

## Docker

```bash
docker build -t netwatch .
docker run -p 8501:8501 netwatch
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

- Add PDF export after the Markdown report
- Save scan history in SQLite instead of CSV
- Add screenshots from a real lab run
- Add device names/vendor lookup for local networks
- Improve Windows/Linux ping handling even more

## Disclaimer

This project is for learning and authorized defensive testing only. Do not scan networks or devices without permission.
