# Deployment Guide

This guide explains how to run NetWatch for a small internal demo or local network lab.

## Option 1: Python virtual environment

```bash
git clone https://github.com/Adam-Ghanem/NetWatch.git
cd NetWatch
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open:

```text
http://localhost:8501
```

## Option 2: Docker

```bash
docker build -t netwatch .
docker run -p 127.0.0.1:8501:8501 netwatch
```

## Option 3: Docker Compose

```bash
docker compose up -d --build
```

Stop it later:

```bash
docker compose down
```

Compose stores operational data in the named volumes `netwatch_data` and
`netwatch_logs`. The published dashboard port is bound to localhost only.

## Optional local API

Run the API on loopback unless you have added proper authentication and an
approved deployment boundary:

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

API scan requests must include `"authorized": true`. Browser origins and Host
headers can be customized with `NETWATCH_CORS_ORIGINS` and
`NETWATCH_API_HOSTS`; wildcard values are intentionally ignored.

## Generated local files

NetWatch creates local operational data when it runs:

```text
data/netwatch.db
data/scan_history.csv
logs/netwatch.log
```

These files are ignored by Git and should stay local to the machine running the app.

## Recommended internal demo setup

- Run NetWatch on a trusted laptop or lab VM.
- Connect it to the authorized lab or company test network only.
- Use a small CIDR range first, such as `/28`, then `/24` if allowed.
- Export Markdown or HTML reports after the scan.
- Do not expose the Streamlit port publicly on the Internet.

## Production notes

NetWatch is a portfolio/lab tool. For real production use, add organization authentication, role-based access control, audit retention rules, and monitoring around the Streamlit service.
