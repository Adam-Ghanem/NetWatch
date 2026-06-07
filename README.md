# NetWatch

NetWatch is a small Python/Streamlit project for basic local network monitoring.

I built it as a cybersecurity/networking portfolio project while practicing Python, network scanning concepts, and defensive security. The goal is simple: check devices on a local network, test one host with ping, scan a short list of common ports, and show the result in a clean dashboard.

> Use this only on networks you own or where you have permission.

## What it does

- Checks if a private/local IP is online using ping
- Scans a local CIDR range such as `192.168.1.0/24`
- Checks common TCP ports like SSH, HTTP, SMB, MySQL and RDP
- Blocks public Internet targets from the app
- Shows basic risk levels and simple hardening advice
- Exports scan results as CSV
- Keeps a local activity log in `logs/netwatch.log`

## Why I made it

I wanted a practical project related to networking and cybersecurity, not just a static website. NetWatch helped me practice:

- Python modules and clean file structure
- Streamlit dashboards
- IP/CIDR validation
- Socket programming basics
- Defensive security thinking
- GitHub project organization

## Tech stack

- Python
- Streamlit
- Pandas
- Plotly
- Pytest

## Project structure

```text
NetWatch/
├── app.py
├── config.py
├── logger.py
├── network_scanner.py
├── ping_checker.py
├── port_scanner.py
├── security.py
├── requirements.txt
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── Dockerfile
├── Makefile
├── LICENSE
├── assets/
│   └── banner.svg
├── data/
│   └── sample_hosts.csv
└── tests/
    └── test_security.py
```

## Installation

Clone the repository:

```bash
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
```

Create and activate a virtual environment:

```bash
python -m venv venv
```

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
- The port advice is basic and defensive.

## Current limits

This is still a beginner/portfolio project. Some things I want to improve later:

- Add PDF report export
- Save scan history in a small database
- Add screenshots after running it on a lab network
- Improve device naming/vendor detection
- Add better error handling for Windows/Linux ping differences

## Tests

```bash
pytest -q
```

## Disclaimer

This project is for learning and authorized defensive testing only. Do not scan networks or devices without permission.
