from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from threading import BoundedSemaphore
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field

from advisory_engine import advice_to_markdown, build_advice
from config import APP_NAME, APP_VERSION, api_allowed_hosts, api_cors_origins
from history_store import add_history, load_history
from host_profiler import profile_host
from inventory_store import (
    add_scan_run,
    asset_inventory,
    asset_open_ports,
    init_db,
    update_asset_ports,
    upsert_hosts,
)
from network_scanner import scan_network
from network_tools import guess_gateway, network_profile
from port_scanner import scan_ports
from report_builder import build_html_report, build_markdown_report
from risk_engine import summarize_exposure, top_recommendations
from security import validate_cidr, validate_target_ip


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=api_allowed_hosts())
app.add_middleware(
    CORSMiddleware,
    allow_origins=api_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

SCAN_SLOT = BoundedSemaphore(value=1)


class NetworkScanRequest(BaseModel):
    cidr: str = Field(default="192.168.1.0/24", min_length=1, max_length=64)
    authorized: bool = Field(default=False)


class HostRequest(BaseModel):
    ip: str = Field(default="192.168.1.1", min_length=1, max_length=64)
    authorized: bool = Field(default=False)


def require_authorization(authorized: bool) -> None:
    if not authorized:
        raise HTTPException(
            status_code=403,
            detail="Confirm that you own or are authorized to check this target.",
        )


@contextmanager
def exclusive_scan():
    if not SCAN_SLOT.acquire(blocking=False):
        raise HTTPException(
            status_code=429, detail="Another network check is already running."
        )
    try:
        yield
    finally:
        SCAN_SLOT.release()


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"app": APP_NAME, "version": APP_VERSION, "status": "ok"}


@app.get("/api/profile")
def profile(
    cidr: str = Query(default="192.168.1.0/24", min_length=1, max_length=64),
) -> dict[str, Any]:
    info = network_profile(cidr)
    return {**info.__dict__, "gateway_guess": guess_gateway(cidr)}


@app.post("/api/scan/network")
def scan_lan(payload: NetworkScanRequest) -> dict[str, Any]:
    require_authorization(payload.authorized)
    validation = validate_cidr(payload.cidr)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.cidr.strip()
    with exclusive_scan():
        results = scan_network(target)
    summary = f"{len(results)} online host(s) found"
    add_history("network", target, summary)
    add_scan_run("network", target, summary)
    upsert_hosts(results)
    return {
        "target": target,
        "online_hosts": len(results),
        "hosts": results,
        "summary": summary,
    }


@app.post("/api/scan/host")
def check_host(payload: HostRequest) -> dict[str, Any]:
    require_authorization(payload.authorized)
    validation = validate_target_ip(payload.ip)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.ip.strip()
    with exclusive_scan():
        result = profile_host(target)
    status = "online" if result.online else "offline"
    msg = f"{result.notes}; latency={result.latency_ms}; ttl={result.ttl}; hostname={result.hostname}"
    add_history("host_profile", target, msg, status=status)
    add_scan_run("host_profile", target, msg, status=status)
    if result.online:
        upsert_hosts(
            [
                {
                    "IP Address": result.ip_address,
                    "Status": "Online",
                    "Details": result.notes,
                }
            ]
        )
    return result.__dict__


@app.post("/api/audit/ports")
def audit_ports(payload: HostRequest) -> dict[str, Any]:
    require_authorization(payload.authorized)
    validation = validate_target_ip(payload.ip)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.ip.strip()
    with exclusive_scan():
        ports = scan_ports(target)
    exposure = summarize_exposure(ports)
    msg = f"{exposure.open_ports} open port(s), level {exposure.level}, score {exposure.score}"
    add_history("ports", target, msg)
    add_scan_run("ports", target, msg)
    update_asset_ports(target, ports, exposure.score, exposure.level)
    return {
        "target": target,
        "ports": ports,
        "exposure": exposure.__dict__,
        "recommendations": top_recommendations(ports),
    }


@app.get("/api/inventory")
def inventory(limit: int = Query(default=500, ge=1, le=2_000)) -> dict[str, Any]:
    assets = asset_inventory(limit=limit)
    return {"count": len(assets), "assets": assets}


@app.get("/api/history")
def history(limit: int = Query(default=25, ge=1, le=200)) -> dict[str, Any]:
    return {"items": load_history(limit=limit)}


@app.get("/api/advisor")
def advisor() -> dict[str, Any]:
    inventory_rows = asset_inventory()
    port_rows = asset_open_ports()
    advice = build_advice(inventory_rows, port_rows, inventory_rows)
    return {**advice.__dict__, "markdown": advice_to_markdown(advice)}


@app.get("/api/reports/markdown", response_class=PlainTextResponse)
def markdown_report() -> str:
    import pandas as pd

    hosts_df = pd.DataFrame(asset_inventory())
    ports_df = pd.DataFrame(asset_open_ports())
    return build_markdown_report(hosts_df, ports_df)


@app.get("/api/reports/html", response_class=HTMLResponse)
def html_report() -> str:
    import pandas as pd

    hosts_df = pd.DataFrame(asset_inventory())
    ports_df = pd.DataFrame(asset_open_ports())
    return build_html_report(hosts_df, ports_df)
