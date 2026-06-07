from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from advisory_engine import advice_to_markdown, build_advice
from config import APP_NAME, APP_VERSION
from export_utils import safe_csv_bytes
from history_store import add_history, load_history
from host_profiler import profile_host
from inventory_store import add_scan_run, asset_inventory, init_db, update_asset_ports, upsert_hosts
from network_scanner import scan_network
from network_tools import guess_gateway, network_profile
from port_scanner import scan_ports
from report_builder import build_html_report, build_markdown_report
from risk_engine import summarize_exposure, top_recommendations
from security import validate_cidr, validate_target_ip

app = FastAPI(title=APP_NAME, version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class NetworkScanRequest(BaseModel):
    cidr: str = Field(default="192.168.1.0/24")


class HostRequest(BaseModel):
    ip: str = Field(default="192.168.1.1")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"app": APP_NAME, "version": APP_VERSION, "status": "ok"}


@app.get("/api/profile")
def profile(cidr: str = "192.168.1.0/24") -> dict[str, Any]:
    info = network_profile(cidr)
    return {**info.__dict__, "gateway_guess": guess_gateway(cidr)}


@app.post("/api/scan/network")
def scan_lan(payload: NetworkScanRequest) -> dict[str, Any]:
    validation = validate_cidr(payload.cidr)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    results = scan_network(payload.cidr)
    summary = f"{len(results)} online host(s) found"
    add_history("network", payload.cidr, summary)
    add_scan_run("network", payload.cidr, summary)
    upsert_hosts(results)
    return {"target": payload.cidr, "online_hosts": len(results), "hosts": results, "summary": summary}


@app.post("/api/scan/host")
def check_host(payload: HostRequest) -> dict[str, Any]:
    validation = validate_target_ip(payload.ip)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    result = profile_host(payload.ip)
    status = "online" if result.online else "offline"
    msg = f"{result.notes}; latency={result.latency_ms}; ttl={result.ttl}; hostname={result.hostname}"
    add_history("host_profile", payload.ip, msg, status=status)
    add_scan_run("host_profile", payload.ip, msg, status=status)
    if result.online:
        upsert_hosts([{"IP Address": result.ip_address, "Status": "Online", "Details": result.notes}])
    return result.__dict__


@app.post("/api/audit/ports")
def audit_ports(payload: HostRequest) -> dict[str, Any]:
    validation = validate_target_ip(payload.ip)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    ports = scan_ports(payload.ip)
    exposure = summarize_exposure(ports)
    msg = f"{exposure.open_ports} open port(s), level {exposure.level}, score {exposure.score}"
    add_history("ports", payload.ip, msg)
    add_scan_run("ports", payload.ip, msg)
    update_asset_ports(payload.ip, ports, exposure.score, exposure.level)
    return {"target": payload.ip, "ports": ports, "exposure": exposure.__dict__, "recommendations": top_recommendations(ports)}


@app.get("/api/inventory")
def inventory() -> dict[str, Any]:
    assets = asset_inventory()
    return {"count": len(assets), "assets": assets}


@app.get("/api/history")
def history(limit: int = 25) -> dict[str, Any]:
    return {"items": load_history(limit=limit)}


@app.get("/api/advisor")
def advisor() -> dict[str, Any]:
    inventory_rows = asset_inventory()
    advice = build_advice([], [], inventory_rows)
    return {**advice.__dict__, "markdown": advice_to_markdown(advice)}


@app.get("/api/reports/markdown", response_class=PlainTextResponse)
def markdown_report() -> str:
    import pandas as pd

    hosts_df = pd.DataFrame(asset_inventory())
    ports_df = pd.DataFrame()
    return build_markdown_report(hosts_df, ports_df)


@app.get("/api/reports/html", response_class=HTMLResponse)
def html_report() -> str:
    import pandas as pd

    hosts_df = pd.DataFrame(asset_inventory())
    ports_df = pd.DataFrame()
    return build_html_report(hosts_df, ports_df)
