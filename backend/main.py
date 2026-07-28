from __future__ import annotations

import hmac
import logging
import os
import secrets
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
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from advisory_engine import advice_to_markdown, build_advice
from ai_advisor import (
    AIProviderError,
    build_deidentified_snapshot,
    request_intelligence_brief,
    safety_configuration_is_usable,
    safety_identifier,
    snapshot_hash,
)
from config import (
    AI_CACHE_TTL_SECONDS,
    AI_DAILY_REQUEST_LIMIT,
    AI_ENABLED,
    AI_MAX_CONCURRENT_REQUESTS,
    AI_MODEL,
    AI_RATE_LIMIT_REQUESTS,
    AI_RATE_LIMIT_WINDOW_SECONDS,
    API_ALLOWED_HOSTS,
    API_ALLOWED_ORIGINS,
    API_DOCS_ENABLED,
    API_RATE_LIMIT_REQUESTS,
    API_RATE_LIMIT_WINDOW_SECONDS,
    APP_NAME,
    APP_VERSION,
    DEFAULT_API_KEY_PLACEHOLDER,
    MAINTENANCE_MAX_DURATION_DAYS,
    MAX_CAPTURE_BYTES,
    MAX_CAPTURE_PACKETS,
    MAX_CAPTURE_ROWS,
    MAX_CONCURRENT_CAPTURE_ANALYSES,
    MAX_CONCURRENT_SCANS,
    MAX_INVENTORY_ROWS,
    MIN_API_KEY_LENGTH,
    SCAN_POLICY_MAX_INTERVAL_MINUTES,
    SCAN_POLICY_MIN_INTERVAL_MINUTES,
    SCHEDULER_ENABLED,
    SCHEDULER_POLL_SECONDS,
)
from enterprise_auth import (
    OIDCAuthenticationError,
    OIDCAuthorizationError,
    OIDCConfigurationError,
    OIDCProviderUnavailableError,
    oidc_configuration_status,
    oidc_settings,
    verify_oidc_token,
)
from export_utils import safe_csv_bytes
from host_profiler import profile_host
from intelligence_store import (
    cached_intelligence_brief,
    daily_provider_request_count,
    intelligence_metrics,
    record_intelligence_failure,
    reserve_intelligence_request,
    save_intelligence_brief,
)
from inventory_store import (
    AuditIntegrityError,
    add_scan_run,
    asset_inventory,
    asset_port_findings,
    audit_integrity_enabled,
    audit_integrity_is_ready,
    database_is_ready,
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
    verify_audit_integrity,
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
from packet_analyzer import CaptureFormatError, analyze_capture
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
    allow_headers=["Authorization", "Content-Type", "X-NetWatch-Key"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(API_ALLOWED_HOSTS))


@app.exception_handler(AuditIntegrityError)
async def audit_integrity_error_handler(request: Request, _: AuditIntegrityError) -> JSONResponse:
    LOGGER.error(
        "audit_integrity_blocked request_id=%s route=%s",
        str(getattr(request.state, "request_id", ""))[:64],
        getattr(request.scope.get("route"), "path", "unmatched"),
    )
    return JSONResponse(
        status_code=503,
        content={"detail": "Audit integrity verification failed; protected operations are paused."},
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    global _http_active_requests
    global _http_request_duration_seconds
    global _http_requests_total
    global _http_server_errors_total

    request.state.request_id = secrets.token_hex(16)
    started = time.perf_counter()
    status_code = 500
    with _http_metrics_lock:
        _http_active_requests += 1
    try:
        response = await call_next(request)
        status_code = response.status_code
    finally:
        elapsed = max(0.0, time.perf_counter() - started)
        with _http_metrics_lock:
            _http_active_requests -= 1
            _http_requests_total += 1
            _http_request_duration_seconds += elapsed
            if status_code >= 500:
                _http_server_errors_total += 1
        route = getattr(request.scope.get("route"), "path", "unmatched")
        LOGGER.info(
            "request_completed request_id=%s method=%s route=%s status=%s duration_ms=%.2f",
            request.state.request_id,
            request.method,
            route,
            status_code,
            elapsed * 1_000,
        )

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
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
_bearer_header = HTTPBearer(auto_error=False)
_MAX_API_RATE_LIMIT_BUCKETS = 50_000
_MAX_INTELLIGENCE_RATE_LIMIT_BUCKETS = 10_000
_rate_lock = threading.Lock()
_rate_events: dict[str, deque[float]] = defaultdict(deque)
_scan_slots = threading.BoundedSemaphore(MAX_CONCURRENT_SCANS)
_capture_slots = threading.BoundedSemaphore(MAX_CONCURRENT_CAPTURE_ANALYSES)
_intelligence_rate_lock = threading.Lock()
_intelligence_rate_events: dict[str, deque[float]] = defaultdict(deque)
_intelligence_slots = threading.BoundedSemaphore(AI_MAX_CONCURRENT_REQUESTS)
_http_metrics_lock = threading.Lock()
_http_requests_total = 0
_http_server_errors_total = 0
_http_active_requests = 0
_http_request_duration_seconds = 0.0


@dataclass(frozen=True)
class AuthContext:
    role: str
    actor_id: str
    auth_method: str
    request_id: str

    @property
    def capabilities(self) -> dict[str, bool]:
        return {
            "read": True,
            "scan": self.role in {"admin", "operator"},
            "manage_assets": self.role == "admin",
            "manage_alerts": self.role in {"admin", "operator"},
            "manage_operations": self.role == "admin",
            "backup": self.role == "admin",
            "view_audit_identity": self.role == "admin",
            "use_intelligence": True,
        }

    @property
    def audit_fields(self) -> dict[str, str]:
        return {
            "actor_id": self.actor_id,
            "auth_method": self.auth_method,
            "request_id": self.request_id,
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


class IntelligenceBriefRequest(BaseModel):
    refresh: bool = False


def _valid_api_key(value: str) -> bool:
    return len(value) >= MIN_API_KEY_LENGTH and value != DEFAULT_API_KEY_PLACEHOLDER


def _role_key_configuration() -> tuple[tuple[tuple[str, str], ...], str]:
    configured: list[tuple[str, str]] = []
    for role, variable in (
        ("admin", "NETWATCH_API_KEY"),
        ("operator", "NETWATCH_OPERATOR_KEY"),
        ("viewer", "NETWATCH_VIEWER_KEY"),
    ):
        key = os.getenv(variable, "").strip()
        if _valid_api_key(key):
            configured.append((role, key))
    values = [key for _, key in configured]
    if len(values) != len(set(values)):
        return (), "invalid"
    return tuple(configured), "configured" if configured else "disabled"


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))[:64]


def _route_template(request: Request) -> str:
    return str(getattr(request.scope.get("route"), "path", request.url.path))[:200]


def _rate_identity(request: Request, context: AuthContext) -> str:
    return f"{context.auth_method}:{context.actor_id}:{_route_template(request)}"


def _bounded_rate_bucket(
    buckets: dict[str, deque[float]],
    *,
    identity: str,
    cutoff: float,
    maximum_buckets: int,
) -> deque[float]:
    events = buckets.get(identity)
    if events is None:
        if len(buckets) >= maximum_buckets:
            stale: list[str] = []
            for bucket_identity, bucket_events in buckets.items():
                while bucket_events and bucket_events[0] < cutoff:
                    bucket_events.popleft()
                if not bucket_events:
                    stale.append(bucket_identity)
            for bucket_identity in stale:
                del buckets[bucket_identity]
        if len(buckets) >= maximum_buckets:
            raise HTTPException(
                status_code=429,
                detail="The rate-limit identity capacity is temporarily full.",
            )
        events = deque()
        buckets[identity] = events
    while events and events[0] < cutoff:
        events.popleft()
    return events


def _enforce_rate_limit(identity: str) -> None:
    now = time.monotonic()
    cutoff = now - API_RATE_LIMIT_WINDOW_SECONDS
    with _rate_lock:
        events = _bounded_rate_bucket(
            _rate_events,
            identity=identity,
            cutoff=cutoff,
            maximum_buckets=_MAX_API_RATE_LIMIT_BUCKETS,
        )
        if len(events) >= API_RATE_LIMIT_REQUESTS:
            raise HTTPException(status_code=429, detail="Too many API requests. Try again later.")
        events.append(now)


def _configured_openai_key() -> str:
    return os.getenv("OPENAI_API_KEY", "").strip()


def _configured_ai_safety_secret() -> str:
    return os.getenv("NETWATCH_AI_SAFETY_SECRET", "").strip()


def _configured_ai_subject_id() -> str:
    return os.getenv("NETWATCH_AI_SUBJECT_ID", "").strip()


def _intelligence_configuration_is_usable(provider_key: str | None = None) -> bool:
    key = _configured_openai_key() if provider_key is None else provider_key
    return bool(
        AI_ENABLED
        and safety_configuration_is_usable(
            api_key=key,
            safety_secret=_configured_ai_safety_secret(),
            subject_id=_configured_ai_subject_id(),
        )
    )


def _enforce_intelligence_rate_limit(identity: str) -> None:
    now = time.monotonic()
    cutoff = now - AI_RATE_LIMIT_WINDOW_SECONDS
    with _intelligence_rate_lock:
        events = _bounded_rate_bucket(
            _intelligence_rate_events,
            identity=identity,
            cutoff=cutoff,
            maximum_buckets=_MAX_INTELLIGENCE_RATE_LIMIT_BUCKETS,
        )
        if len(events) >= AI_RATE_LIMIT_REQUESTS:
            raise HTTPException(
                status_code=429,
                detail="Intelligence request limit reached. Try again later.",
            )
        events.append(now)


def require_api_access(
    request: Request,
    supplied_key: str | None = Security(_api_key_header),
    bearer: HTTPAuthorizationCredentials | None = Security(_bearer_header),
) -> AuthContext:
    authorization_headers = request.headers.getlist("authorization")
    role_key_headers = request.headers.getlist("x-netwatch-key")
    if len(authorization_headers) > 1 or len(role_key_headers) > 1:
        raise HTTPException(
            status_code=401,
            detail="Ambiguous authentication headers are not accepted.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if authorization_headers and bearer is None:
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid enterprise identity token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    _, oidc_status = oidc_configuration_status()
    if oidc_status == "invalid":
        raise HTTPException(
            status_code=503,
            detail="Enterprise identity is not configured safely.",
        )
    if bearer is not None:
        try:
            identity = verify_oidc_token(bearer.credentials)
        except OIDCConfigurationError as exc:
            raise HTTPException(
                status_code=503,
                detail="Enterprise identity is not configured safely.",
            ) from exc
        except OIDCProviderUnavailableError as exc:
            raise HTTPException(
                status_code=503,
                detail="Enterprise identity is temporarily unavailable.",
            ) from exc
        except OIDCAuthenticationError as exc:
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid enterprise identity token.",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc
        except OIDCAuthorizationError as exc:
            raise HTTPException(
                status_code=403,
                detail="The enterprise identity has no assigned NetWatch role.",
            ) from exc
        context = AuthContext(
            role=identity.role,
            actor_id=f"oidc:{identity.subject}",
            auth_method="oidc",
            request_id=_request_id(request),
        )
        _enforce_rate_limit(_rate_identity(request, context))
        return context

    configured, role_keys_status = _role_key_configuration()
    if role_keys_status == "invalid":
        raise HTTPException(
            status_code=503,
            detail="NetWatch role keys are not configured with unique values.",
        )
    if not configured:
        oidc_ready, _ = oidc_configuration_status()
        if oidc_ready:
            raise HTTPException(
                status_code=401,
                detail="A company SSO session or valid NetWatch role key is required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        raise HTTPException(
            status_code=503,
            detail=(
                "NetWatch access is disabled until role keys or enterprise "
                "identity are configured."
            ),
        )

    candidate = supplied_key or ""
    matches = [hmac.compare_digest(candidate, expected_key) for _, expected_key in configured]
    matched_role = next(
        (role for (role, _), matched in zip(configured, matches) if matched),
        None,
    )
    if matched_role is None:
        raise HTTPException(
            status_code=401,
            detail="Missing or invalid NetWatch API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    context = AuthContext(
        role=matched_role,
        actor_id=f"shared-key:{matched_role}",
        auth_method="api_key",
        request_id=_request_id(request),
    )
    _enforce_rate_limit(_rate_identity(request, context))
    return context


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


def _require_audit_integrity_ready() -> None:
    if not audit_integrity_is_ready(use_cache=False):
        raise HTTPException(
            status_code=503,
            detail="Audit integrity verification failed; protected operations are paused.",
        )


def require_audited_operator_access(
    context: AuthContext = Depends(require_operator_access),
) -> AuthContext:
    _require_audit_integrity_ready()
    return context


def require_audited_admin_access(
    context: AuthContext = Depends(require_admin_access),
) -> AuthContext:
    _require_audit_integrity_ready()
    return context


def _require_authorization(authorized: bool) -> None:
    if not authorized:
        raise HTTPException(
            status_code=403,
            detail=(
                "Explicit authorization confirmation is required for "
                "network checks and captures."
            ),
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


@contextmanager
def _capture_slot() -> Iterator[None]:
    acquired = _capture_slots.acquire(blocking=False)
    if not acquired:
        raise HTTPException(
            status_code=429,
            detail="Another capture analysis is already running.",
        )
    try:
        yield
    finally:
        _capture_slots.release()


async def _bounded_capture_body(request: Request) -> bytes:
    encodings = request.headers.get("content-encoding", "identity").strip().lower()
    if encodings not in {"", "identity"}:
        raise HTTPException(status_code=415, detail="Compressed capture uploads are not accepted.")

    raw_lengths = [
        value for key, value in request.scope.get("headers", []) if key.lower() == b"content-length"
    ]
    if len(raw_lengths) > 1:
        raise HTTPException(status_code=400, detail="Ambiguous Content-Length headers.")
    if raw_lengths:
        try:
            declared_length = int(raw_lengths[0].decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.") from exc
        if declared_length < 0:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header.")
        if declared_length > MAX_CAPTURE_BYTES:
            raise HTTPException(status_code=413, detail="Capture exceeds the upload limit.")

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > MAX_CAPTURE_BYTES:
            raise HTTPException(status_code=413, detail="Capture exceeds the upload limit.")
        body.extend(chunk)
    if not body:
        raise HTTPException(status_code=400, detail="Choose a non-empty PCAP or PCAPNG file.")
    return bytes(body)


@contextmanager
def _intelligence_slot() -> Iterator[None]:
    acquired = _intelligence_slots.acquire(blocking=False)
    if not acquired:
        raise HTTPException(
            status_code=429,
            detail="The intelligence service is already processing its safe concurrency limit.",
        )
    try:
        yield
    finally:
        _intelligence_slots.release()


def _intelligence_snapshot() -> dict[str, Any]:
    inventory_rows = asset_inventory()
    return build_deidentified_snapshot(
        inventory_rows=inventory_rows,
        port_rows=asset_port_findings(),
        alert_rows=recent_alerts(limit=200),
        change_rows=recent_asset_events(limit=200),
        operation_metrics=operations_metrics(),
    )


def _public_intelligence_brief(
    response: dict[str, Any],
    *,
    model: str,
    generated_at: str,
    expires_at: str,
    cached: bool,
) -> dict[str, Any]:
    return {
        "brief": response,
        "model": model,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "cached": cached,
        "data_scope": "Aggregated and de-identified operational evidence only.",
        "human_review_required": True,
    }


def _execute_network_scan(
    target: str,
    *,
    actor_role: str,
    action: str,
    actor_id: str = "",
    auth_method: str = "",
    request_id: str = "",
) -> dict[str, Any]:
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
    record_audit_event(
        actor_role,
        action,
        target,
        "completed",
        details,
        actor_id=actor_id,
        auth_method=auth_method,
        request_id=request_id,
    )
    return {
        "target": target,
        "online_hosts": len(results),
        "hosts": results,
        "summary": changes.summary,
        "changes": changes.as_dict(),
        "alerts_created": alerts_created,
        "alerts_refreshed": alerts_refreshed,
    }


def _run_scan_policy(
    policy: dict[str, Any],
    *,
    actor_role: str,
    action: str,
    actor_id: str = "",
    auth_method: str = "",
    request_id: str = "",
) -> dict[str, Any]:
    policy_id = int(policy["id"])
    target = str(policy["cidr"])
    try:
        result = _execute_network_scan(
            target,
            actor_role=actor_role,
            action=action,
            actor_id=actor_id,
            auth_method=auth_method,
            request_id=request_id,
        )
    except HTTPException as exc:
        status = "deferred" if exc.status_code == 429 else "failed"
        complete_scan_policy(policy_id, status=status, summary=str(exc.detail))
        record_audit_event(
            actor_role,
            action,
            target,
            status,
            str(exc.detail),
            actor_id=actor_id,
            auth_method=auth_method,
            request_id=request_id,
        )
        raise
    except Exception as exc:
        summary = f"Scanner failed with {type(exc).__name__}."
        complete_scan_policy(policy_id, status="failed", summary=summary)
        record_audit_event(
            actor_role,
            action,
            target,
            "failed",
            summary,
            actor_id=actor_id,
            auth_method=auth_method,
            request_id=request_id,
        )
        raise
    complete_scan_policy(policy_id, status="completed", summary=result["summary"])
    return {"policy_id": policy_id, **result}


def run_due_scan_policies_once() -> int:
    if not audit_integrity_is_ready(use_cache=False):
        LOGGER.error("scheduler_paused reason=audit_integrity_not_ready")
        return 0
    claimed = claim_due_scan_policies(limit=1)
    completed = 0
    for policy in claimed:
        try:
            _run_scan_policy(
                policy,
                actor_role="scheduler",
                action="scheduled_network_scan",
                actor_id="system:scheduler",
                auth_method="system",
                request_id=secrets.token_hex(16),
            )
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


def _access_health() -> dict[str, Any]:
    configured, role_keys_status = _role_key_configuration()
    oidc_ready, oidc_status = oidc_configuration_status()
    oidc_scanning_enabled = False
    if oidc_ready:
        settings = oidc_settings()
        oidc_scanning_enabled = bool(settings.admin_groups or settings.operator_groups)
    auth_methods = []
    if configured:
        auth_methods.append("api_key")
    if oidc_ready:
        auth_methods.append("oidc")
    return {
        "access_enabled": bool(configured) or oidc_ready,
        "scanning_enabled": (
            any(role in {"admin", "operator"} for role, _ in configured) or oidc_scanning_enabled
        ),
        "auth_methods": auth_methods,
        "role_keys_status": role_keys_status,
        "oidc_status": oidc_status,
    }


@app.get("/api/health/live")
def liveness() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/health/ready")
def readiness() -> Response:
    access = _access_health()
    database_ready = database_is_ready()
    oidc_configuration_valid = access["oidc_status"] != "invalid"
    audit_ready = audit_integrity_is_ready()
    ready = bool(
        database_ready
        and access["access_enabled"]
        and access["role_keys_status"] != "invalid"
        and oidc_configuration_valid
        and audit_ready
    )
    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "not_ready",
            "database": "ready" if database_ready else "unavailable",
            "access": "ready" if access["access_enabled"] else "unconfigured",
            "role_keys": access["role_keys_status"],
            "oidc": access["oidc_status"],
            "audit_integrity": "ready" if audit_ready else "invalid_or_disabled",
        },
    )


@app.get("/api/health")
def health() -> dict[str, Any]:
    access = _access_health()
    return {
        "app": APP_NAME,
        "version": APP_VERSION,
        "status": "ok",
        **access,
        "scheduler_enabled": SCHEDULER_ENABLED,
        "intelligence_enabled": _intelligence_configuration_is_usable(),
        "audit_integrity_enabled": audit_integrity_enabled(),
    }


@app.get("/api/metrics", response_class=PlainTextResponse)
def metrics(_: AuthContext = Depends(require_api_access)) -> PlainTextResponse:
    snapshot = operations_metrics()
    intelligence = intelligence_metrics()
    with _http_metrics_lock:
        http_snapshot = {
            "requests": _http_requests_total,
            "server_errors": _http_server_errors_total,
            "active_requests": _http_active_requests,
            "duration_seconds": _http_request_duration_seconds,
        }
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
        "netwatch_intelligence_provider_requests_total": intelligence["provider_requests"],
        "netwatch_intelligence_completed_total": intelligence["completed"],
        "netwatch_intelligence_failed_total": intelligence["failed"],
        "netwatch_intelligence_active_cache_entries": intelligence["active_cache"],
        "netwatch_audit_integrity_enabled": int(audit_integrity_enabled()),
        "netwatch_http_requests_total": http_snapshot["requests"],
        "netwatch_http_server_errors_total": http_snapshot["server_errors"],
        "netwatch_http_active_requests": http_snapshot["active_requests"],
        "netwatch_http_request_duration_seconds_total": http_snapshot["duration_seconds"],
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
    return {
        "role": context.role,
        "capabilities": context.capabilities,
        "auth_method": context.auth_method,
        "actor_id": context.actor_id,
    }


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
    context: AuthContext = Depends(require_audited_operator_access),
) -> dict[str, Any]:
    _require_authorization(payload.authorized)
    validation = validate_cidr(payload.cidr)
    if not validation.ok:
        raise HTTPException(status_code=400, detail=validation.error)
    target = validation.value or payload.cidr
    return _execute_network_scan(
        target,
        actor_role=context.role,
        action="network_scan",
        **context.audit_fields,
    )


@app.post("/api/scan/host")
def check_host(
    payload: HostRequest,
    context: AuthContext = Depends(require_audited_operator_access),
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
        f"{result.notes}; latency={result.latency_ms}; ttl={result.ttl}; "
        f"hostname={result.hostname}; device={result.device_name}; os={result.os_hint}"
    )
    scan_run_id = add_scan_run("host_profile", target, msg, status=status)
    if result.online:
        upsert_hosts(
            [
                {
                    "IP Address": result.ip_address,
                    "Status": "Online",
                    "Details": result.notes,
                    "Device Name": result.device_name,
                    "Hostname": result.hostname,
                    "Device Type": result.device_type,
                    "Manufacturer": result.manufacturer,
                    "Device Model": result.device_model,
                    "Operating System": result.os_hint,
                    "Identity Confidence": result.identity_confidence,
                    "Identity Evidence": result.identity_evidence,
                    "MAC Address": result.mac_address,
                    "MAC Address Type": result.mac_address_type,
                    "TTL": result.ttl if result.ttl is not None else "-",
                }
            ],
            source="host check",
            scan_run_id=scan_run_id,
        )
    record_audit_event(
        context.role,
        "host_check",
        target,
        "completed",
        f"Status: {status}.",
        **context.audit_fields,
    )
    return result.__dict__


@app.post("/api/audit/ports")
def audit_ports(
    payload: HostRequest,
    context: AuthContext = Depends(require_audited_operator_access),
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
    record_audit_event(
        context.role,
        "port_audit",
        target,
        "completed",
        msg,
        **context.audit_fields,
    )
    return {
        "target": target,
        "ports": ports,
        "exposure": exposure.__dict__,
        "recommendations": top_recommendations(ports),
    }


@app.post("/api/traffic/analyze")
async def analyze_traffic(
    request: Request,
    authorized: bool = Query(default=False),
    include_dns_names: bool = Query(default=False),
    context: AuthContext = Depends(require_audited_operator_access),
) -> dict[str, object]:
    """Analyze bounded PCAP metadata without retaining packet payloads."""

    _require_authorization(authorized)
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    allowed_media_types = {
        "application/octet-stream",
        "application/vnd.tcpdump.pcap",
        "application/vnd.tcpdump.pcapng",
        "application/x-pcap",
        "application/x-pcapng",
    }
    if media_type not in allowed_media_types:
        raise HTTPException(
            status_code=415,
            detail="Upload the capture as PCAP, PCAPNG, or application/octet-stream.",
        )
    capture = await _bounded_capture_body(request)
    capture_size = len(capture)
    try:
        with _capture_slot():
            result = await run_in_threadpool(
                analyze_capture,
                capture,
                maximum_bytes=MAX_CAPTURE_BYTES,
                maximum_packets=MAX_CAPTURE_PACKETS,
                maximum_rows=MAX_CAPTURE_ROWS,
                include_dns_names=include_dns_names,
            )
    except CaptureFormatError as exc:
        record_audit_event(
            context.role,
            "traffic_capture_analysis",
            "uploaded_capture",
            "rejected",
            f"Capture format validation failed; bytes={capture_size}.",
            **context.audit_fields,
        )
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:  # pragma: no cover - malformed-capture safety boundary
        LOGGER.exception("capture_analysis_failed request_id=%s", context.request_id)
        record_audit_event(
            context.role,
            "traffic_capture_analysis",
            "uploaded_capture",
            "failed",
            f"Capture analysis failed safely; bytes={capture_size}.",
            **context.audit_fields,
        )
        raise HTTPException(
            status_code=500,
            detail="Capture analysis failed safely without retaining the upload.",
        ) from exc

    record_audit_event(
        context.role,
        "traffic_capture_analysis",
        "uploaded_capture",
        "completed",
        (
            f"format={result['format']}; bytes={capture_size}; "
            f"packets={result['packets_analyzed']}; payload_retained=false"
        ),
        **context.audit_fields,
    )
    return result


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
    context: AuthContext = Depends(require_audited_admin_access),
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
            **context.audit_fields,
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
    context: AuthContext = Depends(require_audited_admin_access),
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
            authorized_by=context.actor_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit_event(
        context.role,
        "scan_policy_created",
        target,
        "completed",
        f"Policy {policy['name']} saved; enabled={policy['enabled']}.",
        **context.audit_fields,
    )
    return {"policy": policy, "scheduler_enabled": SCHEDULER_ENABLED}


@app.patch("/api/scan-policies/{policy_id}")
def edit_scan_policy(
    policy_id: int,
    payload: ScanPolicyUpdateRequest,
    context: AuthContext = Depends(require_audited_admin_access),
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
        **context.audit_fields,
    )
    return {"policy": policy, "scheduler_enabled": SCHEDULER_ENABLED}


@app.post("/api/scan-policies/{policy_id}/run")
def run_scan_policy_now(
    policy_id: int,
    payload: PolicyRunRequest,
    context: AuthContext = Depends(require_audited_operator_access),
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
        return _run_scan_policy(
            policy,
            actor_role=context.role,
            action="scan_policy_run",
            **context.audit_fields,
        )
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
    context: AuthContext = Depends(require_audited_admin_access),
) -> dict[str, Any]:
    try:
        window = create_maintenance_window(
            name=payload.name,
            starts_at=payload.starts_at,
            ends_at=payload.ends_at,
            reason=payload.reason,
            policy_id=payload.policy_id,
            enabled=payload.enabled,
            created_by=context.actor_id,
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
        **context.audit_fields,
    )
    return {"window": window}


@app.patch("/api/maintenance-windows/{window_id}")
def edit_maintenance_window(
    window_id: int,
    payload: MaintenanceWindowUpdateRequest,
    context: AuthContext = Depends(require_audited_admin_access),
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
        **context.audit_fields,
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
    context: AuthContext = Depends(require_audited_operator_access),
) -> dict[str, Any]:
    try:
        alert = update_operation_alert(
            alert_id,
            actor_role=context.actor_id,
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
        **context.audit_fields,
    )
    return {"alert": alert}


@app.get("/api/backups/database")
def database_backup(context: AuthContext = Depends(require_audited_admin_access)) -> Response:
    content = database_backup_bytes()
    record_audit_event(
        context.role,
        "database_backup",
        "netwatch.db",
        "completed",
        "Consistent SQLite snapshot generated for authorized download.",
        **context.audit_fields,
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


@app.get("/api/audit-log")
def audit_log(
    limit: int = Query(default=100, ge=1, le=1_000),
    _: AuthContext = Depends(require_admin_access),
) -> dict[str, Any]:
    items = recent_audit_log(limit=limit, include_identity=True)
    return {"count": len(items), "items": items}


@app.get("/api/audit-log/integrity")
def audit_log_integrity(
    _: AuthContext = Depends(require_admin_access),
) -> dict[str, object]:
    return verify_audit_integrity()


@app.get("/api/advisor", dependencies=[Depends(require_api_access)])
def advisor() -> dict[str, Any]:
    inventory_rows = asset_inventory()
    port_rows = asset_port_findings()
    change_rows = recent_asset_events(limit=25)
    advice = build_advice(inventory_rows, port_rows, inventory_rows, change_rows)
    return {**advice.__dict__, "markdown": advice_to_markdown(advice)}


@app.get("/api/intelligence/status")
def intelligence_status(_: AuthContext = Depends(require_api_access)) -> dict[str, Any]:
    provider_requests = daily_provider_request_count()
    available = _intelligence_configuration_is_usable()
    return {
        "available": available,
        "model": AI_MODEL if available else "",
        "daily_request_limit": AI_DAILY_REQUEST_LIMIT,
        "daily_requests_used": provider_requests,
        "daily_requests_remaining": max(0, AI_DAILY_REQUEST_LIMIT - provider_requests),
        "cache_ttl_seconds": AI_CACHE_TTL_SECONDS,
        "data_scope": "Aggregated and de-identified operational evidence only.",
        "local_advisor_available": True,
    }


@app.post("/api/intelligence/brief")
def intelligence_brief(
    payload: IntelligenceBriefRequest,
    request: Request,
    context: AuthContext = Depends(require_api_access),
) -> dict[str, Any]:
    if payload.refresh and context.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access is required to bypass the intelligence cache.",
        )

    snapshot = _intelligence_snapshot()
    digest = snapshot_hash(snapshot)
    if not payload.refresh:
        cached = cached_intelligence_brief(digest)
        if cached is not None:
            return _public_intelligence_brief(
                cached["response"],
                model=str(cached["model"]),
                generated_at=str(cached["created_at"]),
                expires_at=str(cached["expires_at"]),
                cached=True,
            )

    provider_key = _configured_openai_key()
    safety_secret = _configured_ai_safety_secret()
    subject_id = _configured_ai_subject_id()
    if (
        not safety_configuration_is_usable(
            api_key=provider_key,
            safety_secret=safety_secret,
            subject_id=subject_id,
        )
        or not AI_ENABLED
    ):
        raise HTTPException(
            status_code=503,
            detail=(
                "NetWatch Intelligence is not configured. "
                "The deterministic local Risk Advisor remains available."
            ),
        )
    _require_audit_integrity_ready()
    _enforce_intelligence_rate_limit(f"{context.auth_method}:{context.actor_id}")
    safety_id = safety_identifier(
        safety_secret=safety_secret,
        subject_id=subject_id,
    )
    try:
        with _intelligence_slot():
            if not reserve_intelligence_request(daily_limit=AI_DAILY_REQUEST_LIMIT):
                raise HTTPException(
                    status_code=429,
                    detail="The daily intelligence request budget has been reached.",
                )
            result = request_intelligence_brief(
                snapshot,
                api_key=provider_key,
                safety_id=safety_id,
                model=AI_MODEL,
            )
        brief = result.brief.model_dump(mode="json")
        now = datetime.now(timezone.utc)
        generated_at = now.isoformat(timespec="seconds")
        expires_at = datetime.fromtimestamp(
            now.timestamp() + AI_CACHE_TTL_SECONDS,
            tz=timezone.utc,
        ).isoformat(timespec="seconds")
        save_intelligence_brief(
            snapshot_hash=digest,
            model=AI_MODEL,
            actor_role=context.role,
            response=brief,
            provider_request_id=result.provider_request_id,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
        )
        record_audit_event(
            context.role,
            "intelligence_brief_generated",
            "de-identified operations snapshot",
            "completed",
            (
                f"Structured defensive brief generated with {AI_MODEL}; "
                f"input_tokens={result.input_tokens}; output_tokens={result.output_tokens}."
            ),
            **context.audit_fields,
        )
        return _public_intelligence_brief(
            brief,
            model=AI_MODEL,
            generated_at=generated_at,
            expires_at=expires_at,
            cached=False,
        )
    except HTTPException:
        raise
    except AIProviderError as exc:
        record_intelligence_failure(
            snapshot_hash=digest,
            model=AI_MODEL,
            actor_role=context.role,
            error_code=exc.code,
        )
        record_audit_event(
            context.role,
            "intelligence_brief_generated",
            "de-identified operations snapshot",
            "failed",
            f"Intelligence request failed safely; code={exc.code}.",
            **context.audit_fields,
        )
        raise HTTPException(status_code=exc.http_status, detail=str(exc)) from exc
    except Exception:
        record_intelligence_failure(
            snapshot_hash=digest,
            model=AI_MODEL,
            actor_role=context.role,
            error_code="internal_error",
        )
        record_audit_event(
            context.role,
            "intelligence_brief_generated",
            "de-identified operations snapshot",
            "failed",
            "Intelligence request failed safely; code=internal_error.",
            **context.audit_fields,
        )
        LOGGER.error("An intelligence request failed safely; code=internal_error.")
        raise HTTPException(
            status_code=503,
            detail="The intelligence service is temporarily unavailable.",
        ) from None


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
