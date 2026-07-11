from __future__ import annotations

import hmac
import os
import sys
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Any, Iterator

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from advisory_engine import advice_to_markdown, build_advice
from config import (
    API_ALLOWED_ORIGINS,
    API_DOCS_ENABLED,
    API_RATE_LIMIT_REQUESTS,
    API_RATE_LIMIT_WINDOW_SECONDS,
    APP_NAME,
    APP_VERSION,
    MAX_CONCURRENT_SCANS,
)
from host_profiler import profile_host
from inventory_store import (
    add_scan_run,
    asset_inventory,
    asset_port_findings,
    init_db,
    recent_scan_runs,
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


app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if API_DOCS_ENABLED else None,
    redoc_url="/redoc" if API_DOCS_ENABLED else None,
    openapi_url="/openapi.json" if API_DOCS_ENABLED else None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(API_ALLOWED_ORIGINS),
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-NetWatch-Key"],
)

_api_key_header = APIKeyHeader(name="X-NetWatch-Key", auto_error=False)
_rate_lock = threading.Lock()
_rate_events: dict[str, deque[float]] = defaultdict(deque)
_scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


class NetworkScanRequest(BaseModel):
    cidr: str = Field(default="192.168.1.0/24", min_length=7, max_length=43)
    authorized: bool = Field(default=False, description="Confirm explicit authorization for this scan.")


class HostRequest(BaseModel):
    ip: str = Field(default="192.168.1.1", min_length=7, max_length=45)
    authorized: bool = Field(default=False, description="Confirm explicit authorization for this check.")


def _configured_api_key() -> str:
    return os.getenv("NETWATCH_API_KEY", "").strip()


def _client_identity(request: Request) -> str:
    host = request.client.host if request.client else "unknown"
    return f"{host}:{request.url.path}"


def _enforce_rate_limit(identity: str) -> None:
    now = time.monotonic()
    cutoff = now - API_RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        events = _rate_events[identity]
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= API_RATE_LIMIT_REQUESTS:
            raise HTTPException(status_code=429, detail="Too many API requests. Try again later.")
        events.append(now)


def require_api_access(
    request: Request,
    supplied_key: str | None = Security(_api_key_header),
) -> None:
    expected_key = _configured_api_key()
    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="NetWatch API scanning is disabled until NETWATCH_API_KEY is configured.",
        )
    if not supplied_key or not hmac.compare_digest(supplied_key, expected_key):
        raise HTTPException(status_code=401, detail="Missing or invalid NetWatch API key.")
    _enforce_rate_limit(_client_identity(request))


def _require_authorization(authorized: bool) -> None:
    if not authorized:
        raise HTTPException(
            status_code=403,
            detail="Explicit authorization confirmation is required for network checks.",
        )


@contextmanager
def _scan_slot() -> Iterator[None]:
    acquired = _scan_slots.acquire(blocking=False)
    if not acquired:
        raise HTTPException(status_code=429, detail="Another scan is already running.")
    try:
        yield
    finally:
        _scan_slots.release()


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "status": "ok",
        "scanning_enabled": bool(_configured_api_key()),
    }


@app.get("/api/profile", dependencies=[Depends(require_api_access)])
def profile(cidr: str = Query(default="192.168.1.0/24", max_length=43)) -> dict[str, Any]:
    validation = validate_cidr(cidr)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    info = network_profile(validation.value or cidr)
    return {**info.__dict__, "gateway_guess": guess_gateway(validation.value or cidr)}


@app.post("/api/scan/network", dependencies=[Depends(require_api_access)])
def scan_lan(payload: NetworkScanRequest) -> dict[str, Any]:
    _require_authorization(payload.authorized)
    validation = validate_cidr(payload.cidr)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.cidr
    with _scan_slot():
        results = scan_network(target)
    summary = f"{len(results)} online host(s) found"
    add_scan_run("network", target, summary)
    upsert_hosts(results)
    return {"target": target, "online_hosts": len(results), "hosts": results, "summary": summary}


@app.post("/api/scan/host", dependencies=[Depends(require_api_access)])
def check_host(payload: HostRequest) -> dict[str, Any]:
    _require_authorization(payload.authorized)
    validation = validate_target_ip(payload.ip)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.ip
    with _scan_slot():
        result = profile_host(target)
    status = "online" if result.online else "offline"
    msg = f"{result.notes}; latency={result.latency_ms}; ttl={result.ttl}; hostname={result.hostname}"
    add_scan_run("host_profile", target, msg, status=status)
    if result.online:
        upsert_hosts([{"IP Address": result.ip_address, "Status": "Online", "Details": result.notes}])
    return result.__dict__


@app.post("/api/audit/ports", dependencies=[Depends(require_api_access)])
def audit_ports(payload: HostRequest) -> dict[str, Any]:
    _require_authorization(payload.authorized)
    validation = validate_target_ip(payload.ip)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.ip
    with _scan_slot():
        ports = scan_ports(target)
    exposure = summarize_exposure(ports)
    msg = f"{exposure.open_ports} open port(s), level {exposure.level}, score {exposure.score}"
    add_scan_run("ports", target, msg)
    update_asset_ports(target, ports, exposure.score, exposure.level)
    return {
        "target": target,
        "ports": ports,
        "exposure": exposure.__dict__,
        "recommendations": top_recommendations(ports),
    }


@app.get("/api/inventory", dependencies=[Depends(require_api_access)])
def inventory() -> dict[str, Any]:
    assets = asset_inventory()
    return {"count": len(assets), "assets": assets}


@app.get("/api/history", dependencies=[Depends(require_api_access)])
def history(limit: int = Query(default=25, ge=1, le=100)) -> dict[str, Any]:
    return {"items": recent_scan_runs(limit=limit)}


@app.get("/api/advisor", dependencies=[Depends(require_api_access)])
def advisor() -> dict[str, Any]:
    inventory_rows = asset_inventory()
    port_rows = asset_port_findings()
    advice = build_advice(inventory_rows, port_rows, inventory_rows)
    return {**advice.__dict__, "markdown": advice_to_markdown(advice)}


@app.get(
    "/api/reports/markdown",
    response_class=PlainTextResponse,
    dependencies=[Depends(require_api_access)],
)
def markdown_report() -> str:
    hosts_df = pd.DataFrame(asset_inventory())
    ports_df = pd.DataFrame(asset_port_findings())
    return build_markdown_report(hosts_df, ports_df)


@app.get(
    "/api/reports/html",
    response_class=HTMLResponse,
    dependencies=[Depends(require_api_access)],
)
def html_report() -> str:
    hosts_df = pd.DataFrame(asset_inventory())
    ports_df = pd.DataFrame(asset_port_findings())
    return build_html_report(hosts_df, ports_df)
