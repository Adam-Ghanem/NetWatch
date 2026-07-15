from __future__ import annotations

import hmac
import logging
import os
import threading
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from advisory_engine import advice_to_markdown, build_advice
from config import (
    API_ALLOWED_HOSTS,
    API_ALLOWED_ORIGINS,
    API_DOCS_ENABLED,
    API_RATE_LIMIT_REQUESTS,
    API_RATE_LIMIT_WINDOW_SECONDS,
    APP_NAME,
    APP_VERSION,
    DEFAULT_API_KEY_PLACEHOLDER,
    MAINTENANCE_MAX_DURATION_DAYS,
    MAX_CONCURRENT_SCANS,
    MAX_INVENTORY_ROWS,
    MIN_API_KEY_LENGTH,
    SCAN_POLICY_MAX_INTERVAL_MINUTES,
    SCAN_POLICY_MIN_INTERVAL_MINUTES,
    SCHEDULER_ENABLED,
    SCHEDULER_POLL_SECONDS,
)
from export_utils import safe_csv_bytes
from host_profiler import profile_host
from inventory_store import (
    add_scan_run,
    asset_inventory,
    asset_port_findings,
    init_db,
    recent_asset_events,
    recent_audit_log,
    recent_network_observations,
    recent_scan_runs,
    record_audit_event,
    record_network_scan,
    update_asset_context,
    update_asset_ports,
    upsert_hosts,
)
from network_scanner import scan_network
from network_tools import guess_gateway, network_profile
from operations_store import (
    MaintenanceWindowActiveError,
    alert_counts,
    claim_due_scan_policies,
    complete_scan_policy,
    create_alerts_for_changes,
    create_maintenance_window,
    create_scan_policy,
    database_backup_bytes,
    maintenance_windows,
    operations_metrics,
    recent_alerts,
    scan_policies,
    set_maintenance_window_enabled,
    start_scan_policy,
    update_operation_alert,
    update_scan_policy,
)
from port_scanner import scan_ports
from report_builder import build_html_report, build_markdown_report
from risk_engine import summarize_exposure, top_recommendations
from security import validate_cidr, validate_target_ip

ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = ROOT / "frontend"
LOGGER = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    scheduler_stop = threading.Event()
    scheduler_thread: threading.Thread | None = None
    if SCHEDULER_ENABLED:
        scheduler_thread = threading.Thread(
            target=_scheduler_loop,
            args=(scheduler_stop,),
            name="netwatch-scheduler",
            daemon=True,
        )
        scheduler_thread.start()
    try:
        yield
    finally:
        scheduler_stop.set()
        if scheduler_thread is not None:
            scheduler_thread.join(timeout=2.0)


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
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "X-NetWatch-Key"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(API_ALLOWED_HOSTS))


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


_api_key_header = APIKeyHeader(name="X-NetWatch-Key", auto_error=False)
_rate_lock = threading.Lock()
_rate_events: dict[str, deque[float]] = defaultdict(deque)
_scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)


@dataclass(frozen=True)
class AuthContext:
    role: str

    @property
    def capabilities(self) -> dict[str, bool]:
        return {
            "read": True,
            "scan": self.role in {"admin", "operator"},
            "manage_assets": self.role == "admin",
            "manage_alerts": self.role in {"admin", "operator"},
            "manage_operations": self.role == "admin",
            "backup": self.role == "admin",
        }


class NetworkScanRequest(BaseModel):
    cidr: str = Field(default="192.168.1.0/24", min_length=7, max_length=43)
    authorized: bool = Field(
        default=False, description="Confirm explicit authorization for this scan."
    )


class HostRequest(BaseModel):
    ip: str = Field(default="192.168.1.1", min_length=7, max_length=45)
    authorized: bool = Field(
        default=False, description="Confirm explicit authorization for this check."
    )


class AssetContextRequest(BaseModel):
    owner: str = Field(default="", max_length=120)
    department: str = Field(default="", max_length=120)
    location: str = Field(default="", max_length=120)
    criticality: Literal["Low", "Medium", "High", "Critical"] = "Medium"
    notes: str = Field(default="", max_length=1_000)


class ScanPolicyCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    cidr: str = Field(min_length=7, max_length=43)
    interval_minutes: int = Field(
        default=60,
        ge=SCAN_POLICY_MIN_INTERVAL_MINUTES,
        le=SCAN_POLICY_MAX_INTERVAL_MINUTES,
    )
    enabled: bool = False
    authorized: bool = Field(
        default=False,
        description="Confirm durable authorization for this scheduled target.",
    )


class ScanPolicyUpdateRequest(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=120)
    interval_minutes: int | None = Field(
        default=None,
        ge=SCAN_POLICY_MIN_INTERVAL_MINUTES,
        le=SCAN_POLICY_MAX_INTERVAL_MINUTES,
    )
    enabled: bool | None = None


class PolicyRunRequest(BaseModel):
    authorized: bool = Field(
        default=False,
        description="Confirm authorization before manually running the approved policy.",
    )


class MaintenanceWindowCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    starts_at: str = Field(min_length=20, max_length=40)
    ends_at: str = Field(min_length=20, max_length=40)
    reason: str = Field(default="", max_length=500)
    policy_id: int | None = Field(default=None, ge=1)
    enabled: bool = True


class MaintenanceWindowUpdateRequest(BaseModel):
    enabled: bool


class AlertUpdateRequest(BaseModel):
    status: Literal["open", "acknowledged", "resolved"] | None = None
    assigned_to: str | None = Field(default=None, max_length=120)
    resolution_note: str | None = Field(default=None, max_length=1_000)


def _valid_api_key(value: str) -> bool:
    return len(value) >= MIN_API_KEY_LENGTH and value != DEFAULT_API_KEY_PLACEHOLDER


def _configured_api_keys() -> tuple[tuple[str, str], ...]:
    configured: list[tuple[str, str]] = []
    for role, variable in (
        ("admin", "NETWATCH_API_KEY"),
        ("operator", "NETWATCH_OPERATOR_KEY"),
        ("viewer", "NETWATCH_VIEWER_KEY"),
    ):
        key = os.getenv(variable, "").strip()
        if _valid_api_key(key):
            configured.append((role, key))
    return tuple(configured)


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
) -> AuthContext:
    configured = _configured_api_keys()
    if not configured:
        raise HTTPException(
            status_code=503,
            detail="NetWatch API access is disabled until a valid role key is configured.",
        )

    candidate = supplied_key or ""
    matches = [hmac.compare_digest(candidate, expected_key) for _, expected_key in configured]
    matched_role = next(
        (role for (role, _), matched in zip(configured, matches) if matched),
        None,
    )
    if matched_role is None:
        raise HTTPException(status_code=401, detail="Missing or invalid NetWatch API key.")
    _enforce_rate_limit(_client_identity(request))
    return AuthContext(role=matched_role)


def require_operator_access(
    context: AuthContext = Depends(require_api_access),
) -> AuthContext:
    if not context.capabilities["scan"]:
        raise HTTPException(status_code=403, detail="Operator or Admin access is required.")
    return context


def require_admin_access(
    context: AuthContext = Depends(require_api_access),
) -> AuthContext:
    if not context.capabilities["manage_assets"]:
        raise HTTPException(status_code=403, detail="Admin access is required.")
    return context


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


def _execute_network_scan(target: str, *, actor_role: str, action: str) -> dict[str, Any]:
    with _scan_slot():
        results = scan_network(target)
    changes = record_network_scan(target, results)
    alert_summary = create_alerts_for_changes(changes)
    alerts_created = alert_summary.created
    alerts_refreshed = alert_summary.refreshed
    details = (
        f"{changes.summary}; {alerts_created} alert(s) created and "
        f"{alerts_refreshed} deduplicated alert(s) refreshed"
    )
    record_audit_event(actor_role, action, target, "completed", details)
    return {
        "target": target,
        "online_hosts": len(results),
        "hosts": results,
        "summary": changes.summary,
        "changes": changes.as_dict(),
        "alerts_created": alerts_created,
        "alerts_refreshed": alerts_refreshed,
    }


def _run_scan_policy(policy: dict[str, Any], *, actor_role: str, action: str) -> dict[str, Any]:
    policy_id = int(policy["id"])
    target = str(policy["cidr"])
    try:
        result = _execute_network_scan(target, actor_role=actor_role, action=action)
    except HTTPException as exc:
        status = "deferred" if exc.status_code == 429 else "failed"
        complete_scan_policy(policy_id, status=status, summary=str(exc.detail))
        record_audit_event(actor_role, action, target, status, str(exc.detail))
        raise
    except Exception as exc:
        summary = f"Scanner failed with {type(exc).__name__}."
        complete_scan_policy(policy_id, status="failed", summary=summary)
        record_audit_event(actor_role, action, target, "failed", summary)
        raise
    complete_scan_policy(policy_id, status="completed", summary=result["summary"])
    return {"policy_id": policy_id, **result}


def run_due_scan_policies_once() -> int:
    claimed = claim_due_scan_policies(limit=1)
    completed = 0
    for policy in claimed:
        try:
            _run_scan_policy(policy, actor_role="scheduler", action="scheduled_network_scan")
            completed += 1
        except Exception:
            LOGGER.exception("A scheduled NetWatch scan did not complete.")
    return completed


def _scheduler_loop(stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            run_due_scan_policies_once()
        except Exception:
            LOGGER.exception("The NetWatch scheduler cycle failed.")
        stop_event.wait(SCHEDULER_POLL_SECONDS)


@app.get("/api/health")
def health() -> dict[str, Any]:
    configured = _configured_api_keys()
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "status": "ok",
        "access_enabled": bool(configured),
        "scanning_enabled": any(role in {"admin", "operator"} for role, _ in configured),
        "scheduler_enabled": SCHEDULER_ENABLED,
    }


@app.get("/api/metrics", response_class=PlainTextResponse)
def metrics(_: AuthContext = Depends(require_api_access)) -> PlainTextResponse:
    snapshot = operations_metrics()
    values = {
        "netwatch_assets_total": snapshot["assets"],
        "netwatch_alerts_open_total": snapshot["open"],
        "netwatch_alerts_acknowledged_total": snapshot["acknowledged"],
        "netwatch_alerts_resolved_total": snapshot["resolved"],
        "netwatch_alerts_overdue_total": snapshot["overdue"],
        "netwatch_alerts_critical_unresolved_total": snapshot["critical_unresolved"],
        "netwatch_scan_policies_total": snapshot["policies"],
        "netwatch_scan_policies_enabled_total": snapshot["enabled_policies"],
        "netwatch_maintenance_windows_active_total": snapshot["active_maintenance"],
        "netwatch_scheduler_enabled": int(SCHEDULER_ENABLED),
    }
    lines = [
        "# NetWatch authenticated operational metrics. No target labels are exported.",
        *(f"# TYPE {name} gauge\n{name} {value}" for name, value in values.items()),
    ]
    return PlainTextResponse(
        "\n".join(lines) + "\n",
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/api/session")
def session(context: AuthContext = Depends(require_api_access)) -> dict[str, Any]:
    return {"role": context.role, "capabilities": context.capabilities}


@app.get("/api/profile", dependencies=[Depends(require_api_access)])
def profile(cidr: str = Query(default="192.168.1.0/24", max_length=43)) -> dict[str, Any]:
    validation = validate_cidr(cidr)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    info = network_profile(validation.value or cidr)
    return {**info.__dict__, "gateway_guess": guess_gateway(validation.value or cidr)}


@app.post("/api/scan/network")
def scan_lan(
    payload: NetworkScanRequest,
    context: AuthContext = Depends(require_operator_access),
) -> dict[str, Any]:
    _require_authorization(payload.authorized)
    validation = validate_cidr(payload.cidr)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.cidr
    return _execute_network_scan(target, actor_role=context.role, action="network_scan")


@app.post("/api/scan/host")
def check_host(
    payload: HostRequest,
    context: AuthContext = Depends(require_operator_access),
) -> dict[str, Any]:
    _require_authorization(payload.authorized)
    validation = validate_target_ip(payload.ip)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.ip
    with _scan_slot():
        result = profile_host(target)
    status = "online" if result.online else "offline"
    msg = (
        f"{result.notes}; latency={result.latency_ms}; ttl={result.ttl}; hostname={result.hostname}"
    )
    scan_run_id = add_scan_run("host_profile", target, msg, status=status)
    if result.online:
        upsert_hosts(
            [{"IP Address": result.ip_address, "Status": "Online", "Details": result.notes}],
            source="host check",
            scan_run_id=scan_run_id,
        )
    record_audit_event(context.role, "host_check", target, "completed", f"Status: {status}.")
    return result.__dict__


@app.post("/api/audit/ports")
def audit_ports(
    payload: HostRequest,
    context: AuthContext = Depends(require_operator_access),
) -> dict[str, Any]:
    _require_authorization(payload.authorized)
    validation = validate_target_ip(payload.ip)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.ip
    with _scan_slot():
        ports = scan_ports(target)
    exposure = summarize_exposure(ports)
    msg = f"{exposure.open_ports} open port(s), level {exposure.level}, score {exposure.score}"
    scan_run_id = add_scan_run("ports", target, msg)
    update_asset_ports(target, ports, exposure.score, exposure.level, scan_run_id=scan_run_id)
    record_audit_event(context.role, "port_audit", target, "completed", msg)
    return {
        "target": target,
        "ports": ports,
        "exposure": exposure.__dict__,
        "recommendations": top_recommendations(ports),
    }


@app.get("/api/inventory", dependencies=[Depends(require_api_access)])
def inventory(
    limit: int = Query(default=500, ge=1, le=MAX_INVENTORY_ROWS),
) -> dict[str, Any]:
    assets = asset_inventory(limit=limit)
    return {"count": len(assets), "assets": assets}


@app.get("/api/inventory/export.csv")
def inventory_export(_: AuthContext = Depends(require_api_access)) -> Response:
    content = safe_csv_bytes(pd.DataFrame(asset_inventory()))
    return Response(
        content=content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="netwatch-inventory.csv"'},
    )


@app.patch("/api/assets/{ip_address}")
def save_asset_context(
    ip_address: str,
    payload: AssetContextRequest,
    context: AuthContext = Depends(require_admin_access),
) -> dict[str, Any]:
    validation = validate_target_ip(ip_address)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or ip_address
    try:
        asset = update_asset_context(
            target,
            owner=payload.owner,
            department=payload.department,
            location=payload.location,
            criticality=payload.criticality,
            notes=payload.notes,
            actor_role=context.role,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Asset was not found in inventory.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"asset": asset}


@app.get("/api/scan-policies")
def list_scan_policies(_: AuthContext = Depends(require_api_access)) -> dict[str, Any]:
    items = scan_policies()
    active_windows = maintenance_windows(active_only=True)
    global_maintenance = any(item["policy_id"] is None for item in active_windows)
    maintained_policy_ids = {
        int(item["policy_id"]) for item in active_windows if item["policy_id"] is not None
    }
    for item in items:
        item["maintenance_active"] = global_maintenance or int(item["id"]) in maintained_policy_ids
    return {
        "count": len(items),
        "items": items,
        "scheduler_enabled": SCHEDULER_ENABLED,
        "minimum_interval_minutes": SCAN_POLICY_MIN_INTERVAL_MINUTES,
        "active_maintenance_count": len(active_windows),
    }


@app.post("/api/scan-policies")
def save_scan_policy(
    payload: ScanPolicyCreateRequest,
    context: AuthContext = Depends(require_admin_access),
) -> dict[str, Any]:
    _require_authorization(payload.authorized)
    validation = validate_cidr(payload.cidr)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.cidr
    try:
        policy = create_scan_policy(
            name=payload.name,
            cidr=target,
            interval_minutes=payload.interval_minutes,
            enabled=payload.enabled,
            authorized_by=context.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit_event(
        context.role,
        "scan_policy_created",
        target,
        "completed",
        f"Policy {policy['name']} saved; enabled={policy['enabled']}.",
    )
    return {"policy": policy, "scheduler_enabled": SCHEDULER_ENABLED}


@app.patch("/api/scan-policies/{policy_id}")
def edit_scan_policy(
    policy_id: int,
    payload: ScanPolicyUpdateRequest,
    context: AuthContext = Depends(require_admin_access),
) -> dict[str, Any]:
    if payload.name is None and payload.interval_minutes is None and payload.enabled is None:
        raise HTTPException(status_code=400, detail="Provide at least one policy field to update.")
    try:
        policy = update_scan_policy(
            policy_id,
            name=payload.name,
            interval_minutes=payload.interval_minutes,
            enabled=payload.enabled,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan policy was not found.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit_event(
        context.role,
        "scan_policy_updated",
        policy["cidr"],
        "completed",
        f"Policy {policy['name']} updated; enabled={policy['enabled']}.",
    )
    return {"policy": policy, "scheduler_enabled": SCHEDULER_ENABLED}


@app.post("/api/scan-policies/{policy_id}/run")
def run_scan_policy_now(
    policy_id: int,
    payload: PolicyRunRequest,
    context: AuthContext = Depends(require_operator_access),
) -> dict[str, Any]:
    _require_authorization(payload.authorized)
    try:
        policy = start_scan_policy(policy_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan policy was not found.") from exc
    except MaintenanceWindowActiveError as exc:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Scan policy is paused by maintenance window "
                f"'{exc.window_name}'. Disable the window before running it."
            ),
        ) from exc
    try:
        return _run_scan_policy(policy, actor_role=context.role, action="scan_policy_run")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail="The approved policy scan failed.") from exc


@app.get("/api/maintenance-windows")
def list_maintenance_windows(
    active_only: bool = Query(default=False),
    _: AuthContext = Depends(require_api_access),
) -> dict[str, Any]:
    items = maintenance_windows(active_only=active_only)
    active_count = len(maintenance_windows(active_only=True))
    return {
        "count": len(items),
        "active_count": active_count,
        "maximum_duration_days": MAINTENANCE_MAX_DURATION_DAYS,
        "items": items,
    }


@app.post("/api/maintenance-windows")
def save_maintenance_window(
    payload: MaintenanceWindowCreateRequest,
    context: AuthContext = Depends(require_admin_access),
) -> dict[str, Any]:
    try:
        window = create_maintenance_window(
            name=payload.name,
            starts_at=payload.starts_at,
            ends_at=payload.ends_at,
            reason=payload.reason,
            policy_id=payload.policy_id,
            enabled=payload.enabled,
            created_by=context.role,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Scan policy was not found.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    target = window["policy_cidr"] or "all approved scan policies"
    record_audit_event(
        context.role,
        "maintenance_window_created",
        target,
        "completed",
        f"Maintenance window {window['name']} saved; enabled={window['enabled']}.",
    )
    return {"window": window}


@app.patch("/api/maintenance-windows/{window_id}")
def edit_maintenance_window(
    window_id: int,
    payload: MaintenanceWindowUpdateRequest,
    context: AuthContext = Depends(require_admin_access),
) -> dict[str, Any]:
    try:
        window = set_maintenance_window_enabled(window_id, enabled=payload.enabled)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Maintenance window was not found.") from exc
    target = window["policy_cidr"] or "all approved scan policies"
    record_audit_event(
        context.role,
        "maintenance_window_updated",
        target,
        "completed",
        f"Maintenance window {window['name']} enabled={window['enabled']}.",
    )
    return {"window": window}


@app.get("/api/alerts")
def alerts(
    status: Literal["open", "acknowledged", "resolved"] | None = Query(default=None),
    severity: Literal["Low", "Medium", "High", "Critical"] | None = Query(default=None),
    overdue_only: bool = Query(default=False),
    limit: int = Query(default=200, ge=1, le=1_000),
    _: AuthContext = Depends(require_api_access),
) -> dict[str, Any]:
    items = recent_alerts(
        status=status,
        severity=severity,
        overdue_only=overdue_only,
        limit=limit,
    )
    counts = alert_counts()
    return {
        "count": len(items),
        "open_count": counts["open"],
        "acknowledged_count": counts["acknowledged"],
        "resolved_count": counts["resolved"],
        "overdue_count": counts["overdue"],
        "critical_unresolved_count": counts["critical_unresolved"],
        "total_count": counts["total"],
        "items": items,
    }


@app.patch("/api/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    payload: AlertUpdateRequest,
    context: AuthContext = Depends(require_operator_access),
) -> dict[str, Any]:
    try:
        alert = update_operation_alert(
            alert_id,
            actor_role=context.role,
            status=payload.status,
            assigned_to=payload.assigned_to,
            resolution_note=payload.resolution_note,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Operational alert was not found.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit_event(
        context.role,
        "alert_status_updated",
        alert["target"],
        "completed",
        (
            f"Alert {alert_id} changed to {alert['status']}; "
            f"assignee={'set' if alert['assigned_to'] else 'unassigned'}; "
            f"resolution_evidence={'set' if alert['resolution_note'] else 'not set'}."
        ),
    )
    return {"alert": alert}


@app.get("/api/backups/database")
def database_backup(context: AuthContext = Depends(require_admin_access)) -> Response:
    content = database_backup_bytes()
    record_audit_event(
        context.role,
        "database_backup",
        "netwatch.db",
        "completed",
        "Consistent SQLite snapshot generated for authorized download.",
    )
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=content,
        media_type="application/vnd.sqlite3",
        headers={
            "Content-Disposition": (f'attachment; filename="netwatch-backup-{timestamp}.sqlite3"')
        },
    )


@app.get("/api/history", dependencies=[Depends(require_api_access)])
def history(limit: int = Query(default=25, ge=1, le=100)) -> dict[str, Any]:
    return {"items": recent_scan_runs(limit=limit)}


@app.get("/api/changes", dependencies=[Depends(require_api_access)])
def changes(limit: int = Query(default=25, ge=1, le=200)) -> dict[str, Any]:
    items = recent_asset_events(limit=limit)
    return {"count": len(items), "items": items}


@app.get("/api/observations", dependencies=[Depends(require_api_access)])
def observations(limit: int = Query(default=100, ge=1, le=1_000)) -> dict[str, Any]:
    items = recent_network_observations(limit=limit)
    return {"count": len(items), "items": items}


@app.get("/api/audit-log", dependencies=[Depends(require_api_access)])
def audit_log(limit: int = Query(default=100, ge=1, le=1_000)) -> dict[str, Any]:
    items = recent_audit_log(limit=limit)
    return {"count": len(items), "items": items}


@app.get("/api/advisor", dependencies=[Depends(require_api_access)])
def advisor() -> dict[str, Any]:
    inventory_rows = asset_inventory()
    port_rows = asset_port_findings()
    change_rows = recent_asset_events(limit=25)
    advice = build_advice(inventory_rows, port_rows, inventory_rows, change_rows)
    return {**advice.__dict__, "markdown": advice_to_markdown(advice)}


@app.get(
    "/api/reports/markdown",
    response_class=PlainTextResponse,
    dependencies=[Depends(require_api_access)],
)
def markdown_report() -> str:
    hosts_df = pd.DataFrame(asset_inventory())
    ports_df = pd.DataFrame(asset_port_findings())
    changes_df = pd.DataFrame(recent_asset_events(limit=50))
    audit_df = pd.DataFrame(recent_audit_log(limit=100))
    alerts_df = pd.DataFrame(recent_alerts(limit=100))
    policies_df = pd.DataFrame(scan_policies())
    maintenance_df = pd.DataFrame(maintenance_windows())
    return build_markdown_report(
        hosts_df,
        ports_df,
        changes_df,
        audit_df,
        alerts_df,
        policies_df,
        maintenance_df,
    )


@app.get(
    "/api/reports/html",
    response_class=HTMLResponse,
    dependencies=[Depends(require_api_access)],
)
def html_report() -> str:
    hosts_df = pd.DataFrame(asset_inventory())
    ports_df = pd.DataFrame(asset_port_findings())
    changes_df = pd.DataFrame(recent_asset_events(limit=50))
    audit_df = pd.DataFrame(recent_audit_log(limit=100))
    alerts_df = pd.DataFrame(recent_alerts(limit=100))
    policies_df = pd.DataFrame(scan_policies())
    maintenance_df = pd.DataFrame(maintenance_windows())
    return build_html_report(
        hosts_df,
        ports_df,
        changes_df,
        audit_df,
        alerts_df,
        policies_df,
        maintenance_df,
    )


if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
