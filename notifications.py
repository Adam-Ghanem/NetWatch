"""Bounded outbound alert delivery for explicitly configured notification channels."""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import logging
import os
import queue
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Literal, cast
from urllib.parse import urlparse

from config import (
    MAX_OPERATION_ALERTS,
    NETWATCH_NOTIFY_DEBOUNCE_SECONDS,
    NETWATCH_NOTIFY_INCLUDE_RAW_TARGETS,
    NETWATCH_NOTIFY_MIN_SEVERITY,
    NETWATCH_SLACK_WEBHOOK_URL,
    NETWATCH_WEBHOOK_URL,
)

NotificationKind = Literal["webhook", "slack"]
DeliveryStatus = Literal[
    "delivered",
    "failed",
    "disabled",
    "debounced",
    "circuit_open",
    "below_minimum_severity",
]

NOTIFICATION_SCHEMA_VERSION = "netwatch-alert/v1"
NOTIFICATION_TIMEOUT_SECONDS = 5
_DNS_RESOLUTION_TIMEOUT_SECONDS = NOTIFICATION_TIMEOUT_SECONDS
_DNS_RESOLVER_WORKERS = 2
_DNS_RESOLVER_QUEUE_SIZE = 2
NOTIFICATION_MAX_RETRIES = 3
NOTIFICATION_RESPONSE_MAX_BYTES = 64 * 1024
_RESPONSE_READ_CHUNK_BYTES = 64 * 1024
NOTIFICATION_CIRCUIT_FAILURE_THRESHOLD = 5
NOTIFICATION_CIRCUIT_COOLDOWN_SECONDS = 300
_BACKOFF_BASE_SECONDS = 0.25
_MAX_URL_LENGTH = 2_048
_SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_ALERT_STATUSES = {"open", "acknowledged", "resolved"}
_ALERT_CATEGORIES = {
    "new_asset",
    "asset_returned",
    "asset_not_observed",
    "notification_test",
}
_NOTIFICATION_EVENTS = {"alert_created", "sla_breached", "notification_test"}
_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}
LOGGER = logging.getLogger(__name__)


class NotificationConfigurationError(ValueError):
    """Raised when an outbound channel URL does not meet the security boundary."""


@dataclass(frozen=True)
class NotificationChannel:
    kind: NotificationKind
    url: str = field(repr=False)
    enabled: bool = False


@dataclass(frozen=True)
class ChannelNotificationResult:
    kind: NotificationKind
    status: DeliveryStatus
    attempts: int = 0


@dataclass(frozen=True)
class NotificationResult:
    reason: str
    channels: tuple[ChannelNotificationResult, ...]

    @property
    def attempted(self) -> int:
        return sum(item.status in {"delivered", "failed"} for item in self.channels)

    @property
    def delivered(self) -> int:
        return sum(item.status == "delivered" for item in self.channels)

    @property
    def failed(self) -> int:
        return sum(item.status == "failed" for item in self.channels)

    @property
    def skipped(self) -> int:
        return len(self.channels) - self.attempted

    def as_public_dict(self) -> dict[str, Any]:
        """Return delivery state without exposing channel URLs or response bodies."""
        return {
            "reason": self.reason,
            "attempted": self.attempted,
            "delivered": self.delivered,
            "failed": self.failed,
            "skipped": self.skipped,
            "channels": [
                {"kind": item.kind, "status": item.status, "attempts": item.attempts}
                for item in self.channels
            ],
        }


@dataclass
class _CircuitState:
    consecutive_failures: int = 0
    open_until: float = 0.0


@dataclass(frozen=True)
class _DeliveryFailure(Exception):
    retryable: bool
    status_code: int | None = None


_state_lock = threading.Lock()
_debounce_state: dict[str, float] = {}
_circuit_state: dict[NotificationKind, _CircuitState] = {
    "webhook": _CircuitState(),
    "slack": _CircuitState(),
}
_notification_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=512)
_worker_lock = threading.Lock()
_workers_started = False


_RESERVED_IPV6_DESTINATION_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("::/96"),
)


def _is_public_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        elif (
            address.is_reserved
            or any(address in network for network in _RESERVED_IPV6_DESTINATION_NETWORKS)
            or address.sixtofour is not None
            or address.teredo is not None
        ):
            # Do not trust is_global alone for IPv6 translation/compatibility ranges.
            return False
    return address.is_global and not address.is_reserved


def validate_notification_url(value: str, *, field_name: str = "Notification URL") -> str:
    """Validate an HTTPS URL and reject non-public literal IP destinations."""
    candidate = str(value).strip()
    try:
        parsed = urlparse(candidate)
        parsed.port
    except ValueError as exc:
        raise NotificationConfigurationError(f"{field_name} is not a valid URL.") from exc
    if (
        not candidate
        or len(candidate) > _MAX_URL_LENGTH
        or parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or any(character.isspace() or not character.isprintable() for character in candidate)
    ):
        raise NotificationConfigurationError(
            f"{field_name} must be an HTTPS URL without credentials, query, or fragment."
        )
    try:
        literal_address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal_address = None
    if literal_address is not None and not _is_public_ip(literal_address):
        raise NotificationConfigurationError(
            f"{field_name} must not target a non-public IP address."
        )
    return candidate


def _configured_value(name: str, fallback: str) -> str:
    return os.getenv(name, fallback).strip()


def notification_channels() -> tuple[NotificationChannel, ...]:
    """Load channels from the deployment environment and fail closed per channel."""
    configured: tuple[tuple[NotificationKind, str, str], ...] = (
        ("webhook", "NETWATCH_WEBHOOK_URL", NETWATCH_WEBHOOK_URL),
        ("slack", "NETWATCH_SLACK_WEBHOOK_URL", NETWATCH_SLACK_WEBHOOK_URL),
    )
    channels: list[NotificationChannel] = []
    for kind, variable, fallback in configured:
        candidate = _configured_value(variable, fallback)
        if not candidate:
            channels.append(NotificationChannel(kind=kind, url="", enabled=False))
            continue
        try:
            safe_url = validate_notification_url(candidate, field_name=variable)
        except NotificationConfigurationError:
            LOGGER.error("notification_channel_disabled kind=%s reason=unsafe_url", kind)
            channels.append(NotificationChannel(kind=kind, url="", enabled=False))
            continue
        channels.append(NotificationChannel(kind=kind, url=safe_url, enabled=True))
    return tuple(channels)


def notification_channel_status() -> list[dict[str, object]]:
    """Return only non-secret channel type and enabled state."""
    return [
        {"kind": channel.kind, "enabled": channel.enabled} for channel in notification_channels()
    ]


def notifications_enabled() -> bool:
    return any(channel.enabled for channel in notification_channels())


def durable_notifications_enabled() -> bool:
    """Opt-in SQLite outbox for case-created notifications, disabled by default."""
    return _runtime_bool("NETWATCH_DURABLE_NOTIFICATIONS_ENABLED", False)


def _runtime_bool(name: str, fallback: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return fallback
    candidate = raw.strip().lower()
    if candidate in _TRUE_VALUES:
        return True
    if candidate in _FALSE_VALUES:
        return False
    return False


def _runtime_debounce_seconds() -> int:
    raw = os.getenv("NETWATCH_NOTIFY_DEBOUNCE_SECONDS")
    if raw is None:
        return NETWATCH_NOTIFY_DEBOUNCE_SECONDS
    try:
        parsed = int(raw.strip())
    except ValueError:
        return NETWATCH_NOTIFY_DEBOUNCE_SECONDS
    return max(30, min(parsed, 86_400))


def _runtime_minimum_severity() -> str:
    candidate = (
        os.getenv("NETWATCH_NOTIFY_MIN_SEVERITY", NETWATCH_NOTIFY_MIN_SEVERITY).strip().title()
    )
    return candidate if candidate in _SEVERITY_RANK else "High"


def alert_meets_notification_threshold(alert: dict[str, Any]) -> bool:
    severity = str(alert.get("severity", "Low")).title()
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK[_runtime_minimum_severity()]


def _bounded_int(value: Any, *, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return 0
    return max(0, min(parsed, maximum))


def _clean(value: Any, max_length: int) -> str:
    return " ".join(str(value or "").split())[:max_length]


def build_alert_notification_payload(alert: dict[str, Any]) -> dict[str, Any]:
    """Build an allowlisted payload that excludes raw operational identifiers by default."""
    severity = str(alert.get("severity", "Low")).title()
    status = str(alert.get("status", "open")).lower()
    category = str(alert.get("category", "other")).lower()
    event = str(alert.get("_notification_event", "alert_created")).lower()
    include_raw_target = _runtime_bool(
        "NETWATCH_NOTIFY_INCLUDE_RAW_TARGETS", NETWATCH_NOTIFY_INCLUDE_RAW_TARGETS
    )
    alert_payload: dict[str, Any] = {
        "reference": f"case-{_bounded_int(alert.get('id'), maximum=10_000_000)}",
        "severity": severity if severity in _SEVERITY_RANK else "Low",
        "status": status if status in _ALERT_STATUSES else "open",
        "category": category if category in _ALERT_CATEGORIES else "other",
        "occurrences": max(1, _bounded_int(alert.get("occurrence_count"), maximum=100_000)),
        "overdue": bool(alert.get("overdue", False) or event == "sla_breached"),
    }
    if include_raw_target:
        target = _clean(alert.get("target"), 200)
        if target:
            alert_payload["target"] = target
    return {
        "schema_version": NOTIFICATION_SCHEMA_VERSION,
        "event": event if event in _NOTIFICATION_EVENTS else "alert_created",
        "source": "NetWatch",
        "privacy": {
            "deidentified": not include_raw_target,
            "raw_target_included": include_raw_target,
        },
        "alert": alert_payload,
    }


def _notification_key(alert: dict[str, Any]) -> str:
    explicit = _clean(alert.get("_notification_key"), 200)
    reference = explicit or "|".join(
        (
            str(_bounded_int(alert.get("id"), maximum=10_000_000)),
            _clean(alert.get("category"), 80),
            _clean(alert.get("target"), 200),
        )
    )
    return hashlib.sha256(reference.encode("utf-8")).hexdigest()


def _claim_debounce(key: str) -> bool:
    now = time.monotonic()
    window = _runtime_debounce_seconds()
    with _state_lock:
        cutoff = now - window
        stale = [state_key for state_key, seen_at in _debounce_state.items() if seen_at <= cutoff]
        for state_key in stale:
            del _debounce_state[state_key]
        previous = _debounce_state.get(key)
        if previous is not None and previous > cutoff:
            return False
        if len(_debounce_state) >= max(100, MAX_OPERATION_ALERTS * 2):
            oldest = min(_debounce_state, key=_debounce_state.__getitem__)
            del _debounce_state[oldest]
        _debounce_state[key] = now
    return True


def _circuit_allows(kind: NotificationKind) -> bool:
    now = time.monotonic()
    with _state_lock:
        return _circuit_state[kind].open_until <= now


def _record_channel_success(kind: NotificationKind) -> None:
    with _state_lock:
        state = _circuit_state[kind]
        state.consecutive_failures = 0
        state.open_until = 0.0


def _record_channel_failure(kind: NotificationKind) -> None:
    now = time.monotonic()
    with _state_lock:
        state = _circuit_state[kind]
        state.consecutive_failures += 1
        if state.consecutive_failures >= NOTIFICATION_CIRCUIT_FAILURE_THRESHOLD:
            state.open_until = now + NOTIFICATION_CIRCUIT_COOLDOWN_SECONDS


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


class _DeadlineHeaderReader:
    """Read HTTP header lines without resetting a shared monotonic deadline."""

    def __init__(self, source: Any, sock: Any, deadline: float) -> None:
        self._source = source
        self._socket = sock
        self._deadline = deadline

    def readline(self, limit: int = -1) -> bytes:
        line = bytearray()
        while limit < 0 or len(line) < limit:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("HTTPS response exceeded its total header-read deadline.")
            self._socket.settimeout(remaining)
            chunk = self._source.read(1)
            if time.monotonic() >= self._deadline:
                raise TimeoutError("HTTPS response exceeded its total header-read deadline.")
            if not chunk:
                break
            line.extend(chunk)
            if chunk == b"\n":
                break
        return bytes(line)


class _DeadlineHTTPResponse(http.client.HTTPResponse):
    """Parse the HTTP status and headers under one monotonic deadline."""

    def __init__(
        self,
        sock: Any,
        debuglevel: int = 0,
        method: str | None = None,
        url: str | None = None,
        *,
        header_timeout: float | None = None,
        header_deadline: float | None = None,
    ) -> None:
        if header_deadline is None:
            if header_timeout is None or header_timeout <= 0:
                raise ValueError("Response header timeout must be positive.")
            header_deadline = time.monotonic() + header_timeout
        elif header_deadline <= time.monotonic():
            raise TimeoutError("HTTPS response exceeded its shared delivery deadline.")
        self._header_socket = sock
        self._header_deadline = header_deadline
        super().__init__(sock, debuglevel=debuglevel, method=method, url=url)

    def begin(self) -> None:
        original_fp = self.fp
        self.fp = cast(
            Any,
            _DeadlineHeaderReader(original_fp, self._header_socket, self._header_deadline),
        )
        try:
            super().begin()
        finally:
            self.fp = original_fp


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a vetted IP while retaining hostname-based TLS verification."""

    def __init__(self, host: str, port: int, address: str, *, timeout: float) -> None:
        self._tls_context = ssl.create_default_context()
        super().__init__(host, port=port, timeout=timeout, context=self._tls_context)
        self._resolved_address = address
        self._delivery_deadline: float | None = None

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._resolved_address, self.port),
            self.timeout,
        )
        self.sock = self._tls_context.wrap_socket(sock, server_hostname=self.host)

    def getresponse(self) -> http.client.HTTPResponse:
        header_timeout = (
            self.timeout if self.timeout is not None else NOTIFICATION_TIMEOUT_SECONDS
        )
        header_deadline = getattr(self, "_delivery_deadline", None)

        class _BoundedHeaderResponse(_DeadlineHTTPResponse):
            def __init__(
                self,
                sock: Any,
                debuglevel: int = 0,
                method: str | None = None,
                url: str | None = None,
            ) -> None:
                super().__init__(
                    sock,
                    debuglevel=debuglevel,
                    method=method,
                    url=url,
                    header_timeout=header_timeout,
                    header_deadline=header_deadline,
                )

        original_response_class = self.response_class
        self.response_class = _BoundedHeaderResponse
        try:
            return super().getresponse()
        finally:
            self.response_class = original_response_class


class _PinnedHTTPResponse:
    """Keep the pinned connection open until the bounded response is consumed."""

    def __init__(
        self,
        connection: _PinnedHTTPSConnection,
        response: http.client.HTTPResponse,
        *,
        deadline: float | None = None,
    ) -> None:
        self._connection = connection
        self._response = response
        if deadline is not None:
            setattr(response, "_netwatch_delivery_deadline", deadline)

    def __enter__(self) -> http.client.HTTPResponse:
        return self._response

    def __exit__(self, *_: Any) -> None:
        try:
            self._response.close()
        finally:
            self._connection.close()


class _BoundedDNSResolver:
    """Resolve webhook hosts with a fixed worker pool and bounded pending queue."""

    def __init__(
        self,
        *,
        workers: int = _DNS_RESOLVER_WORKERS,
        queue_size: int = _DNS_RESOLVER_QUEUE_SIZE,
        timeout: float = _DNS_RESOLUTION_TIMEOUT_SECONDS,
    ) -> None:
        if workers < 1 or queue_size < 1 or timeout <= 0:
            raise ValueError("DNS resolver limits must be positive.")
        self._worker_count = workers
        self._timeout = timeout
        self._jobs: queue.Queue[
            tuple[str, int, threading.Event, threading.Event, dict[str, Any]]
        ] = queue.Queue(maxsize=queue_size)
        self._start_lock = threading.Lock()
        self._workers_started = 0

    def _worker(self) -> None:
        while True:
            host, port, completed, cancelled, result = self._jobs.get()
            try:
                if not cancelled.is_set():
                    try:
                        result["records"] = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                    except Exception as exc:
                        result["error"] = (
                            exc if isinstance(exc, OSError) else OSError("DNS resolution failed.")
                        )
            finally:
                completed.set()
                self._jobs.task_done()

    def _ensure_workers(self) -> None:
        with self._start_lock:
            while self._workers_started < self._worker_count:
                index = self._workers_started
                worker = threading.Thread(
                    target=self._worker,
                    name=f"netwatch-webhook-dns-{index + 1}",
                    daemon=True,
                )
                try:
                    worker.start()
                except RuntimeError as exc:
                    if self._workers_started == 0:
                        raise OSError("DNS resolver worker startup failed.") from exc
                    # Keep the workers that did start; retry the missing slots
                    # on a later delivery instead of marking a partial pool complete.
                    break
                self._workers_started += 1

    def resolve(
        self, host: str, port: int, deadline: float | None = None
    ) -> list[tuple[Any, ...]]:
        """Return resolver records within both resolver and delivery deadlines."""
        if deadline is not None and deadline <= time.monotonic():
            raise TimeoutError("DNS resolution timed out.")
        self._ensure_workers()
        if deadline is not None and deadline <= time.monotonic():
            raise TimeoutError("DNS resolution timed out.")
        completed = threading.Event()
        cancelled = threading.Event()
        result: dict[str, Any] = {}
        try:
            self._jobs.put_nowait((host, port, completed, cancelled, result))
        except queue.Full as exc:
            raise TimeoutError("DNS resolver queue is full.") from exc
        wait_timeout = self._timeout
        if deadline is not None:
            wait_timeout = min(wait_timeout, deadline - time.monotonic())
        if wait_timeout <= 0 or not completed.wait(wait_timeout):
            cancelled.set()
            raise TimeoutError("DNS resolution timed out.")
        error = result.get("error")
        if error is not None:
            raise error
        records = result.get("records")
        if not isinstance(records, list):
            raise OSError("DNS resolution returned no usable records.")
        return records


_DNS_RESOLVER = _BoundedDNSResolver()


def _public_https_addresses(
    host: str, port: int, deadline: float | None = None
) -> list[str]:
    """Resolve once and reject the whole hostname if any answer is non-public."""
    records = _DNS_RESOLVER.resolve(host, port, deadline)
    addresses: list[str] = []
    for family, _, _, _, sockaddr in records:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        raw_address = str(sockaddr[0])
        if "%" in raw_address:
            raise NotificationConfigurationError(
                "Notification destination resolves to a non-public address."
            )
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise NotificationConfigurationError(
                "Notification destination could not be validated."
            ) from exc
        if not _is_public_ip(address):
            raise NotificationConfigurationError(
                "Notification destination resolves to a non-public address."
            )
        normalized = str(address)
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise OSError("Notification destination did not resolve to a usable address.")
    return addresses


def open_public_https_without_redirects(
    request: urllib.request.Request, timeout: float
) -> _PinnedHTTPResponse:
    """Connect to a validated public IP within one shared per-attempt deadline."""
    parsed = urlparse(request.full_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise NotificationConfigurationError("Outbound destination must use HTTPS.")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise NotificationConfigurationError("Outbound destination port is invalid.") from exc
    if timeout <= 0:
        raise ValueError("Outbound HTTPS delivery timeout must be positive.")
    delivery_deadline = time.monotonic() + timeout
    addresses = _public_https_addresses(parsed.hostname, port, delivery_deadline)
    last_error: Exception | None = None
    for address in addresses:
        remaining = delivery_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                "Outbound HTTPS delivery exceeded its shared delivery deadline."
            ) from last_error
        connection = _PinnedHTTPSConnection(
            parsed.hostname, port, address, timeout=remaining
        )
        try:
            connection.connect()
        except (http.client.HTTPException, OSError) as exc:
            connection.close()
            last_error = exc
            if time.monotonic() >= delivery_deadline:
                raise TimeoutError(
                    "Outbound HTTPS delivery exceeded its shared delivery deadline."
                ) from exc
            continue
        if time.monotonic() >= delivery_deadline:
            connection.close()
            raise TimeoutError(
                "Outbound HTTPS delivery exceeded its shared delivery deadline."
            )
        try:
            connection._delivery_deadline = delivery_deadline
            remaining = delivery_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "Outbound HTTPS delivery exceeded its shared delivery deadline."
                )
            connection.timeout = remaining
            connected_socket = getattr(connection, "sock", None)
            if connected_socket is not None:
                connected_socket.settimeout(remaining)
            connection.request(
                request.get_method(),
                request.selector,
                body=request.data,
                headers=dict(request.header_items()),
            )
            remaining = delivery_deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    "Outbound HTTPS delivery exceeded its shared delivery deadline."
                )
            connection.timeout = remaining
            if connected_socket is not None:
                connected_socket.settimeout(remaining)
            response = connection.getresponse()
        except (http.client.HTTPException, OSError):
            connection.close()
            raise
        return _PinnedHTTPResponse(connection, response, deadline=delivery_deadline)
    if last_error is not None:
        raise last_error
    raise OSError("Notification destination could not be reached.")


def _open_without_redirects(request: urllib.request.Request, timeout: int) -> Any:
    return open_public_https_without_redirects(request, timeout=timeout)


def _response_socket(response: Any) -> Any | None:
    """Find the socket behind an HTTP response without assuming one wrapper depth."""
    pending = [response]
    visited: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in visited:
            continue
        visited.add(id(current))
        candidate = getattr(current, "_sock", None)
        if callable(getattr(candidate, "settimeout", None)):
            return candidate
        for attribute in ("fp", "raw"):
            nested = getattr(current, attribute, None)
            if nested is not None:
                pending.append(nested)
    return None


def read_bounded_response(
    response: Any,
    *,
    max_bytes: int,
    timeout: float,
    deadline: float | None = None,
) -> bytes:
    """Read incrementally under a body deadline capped by the delivery attempt deadline."""
    if max_bytes < 0 or timeout <= 0:
        raise ValueError("Response byte and time limits must be positive.")

    response_socket = _response_socket(response)
    reader = getattr(response, "read1", None)
    if response_socket is None or not callable(reader):
        raise TimeoutError("HTTPS response lacks bounded incremental-read support.")

    body_deadline = time.monotonic() + timeout
    if deadline is not None:
        body_deadline = min(body_deadline, deadline)
    chunks: list[bytes] = []
    total = 0
    while total <= max_bytes:
        remaining = body_deadline - time.monotonic()
        if remaining <= 0:
            message = (
                "HTTPS response exceeded its shared delivery deadline."
                if deadline is not None
                else "HTTPS response exceeded its total body-read deadline."
            )
            raise TimeoutError(message)
        try:
            response_socket.settimeout(remaining)
        except (OSError, ValueError) as exc:
            raise TimeoutError("HTTPS response socket is unavailable.") from exc

        chunk = reader(min(_RESPONSE_READ_CHUNK_BYTES, max_bytes + 1 - total))
        if time.monotonic() >= body_deadline:
            message = (
                "HTTPS response exceeded its shared delivery deadline."
                if deadline is not None
                else "HTTPS response exceeded its total body-read deadline."
            )
            raise TimeoutError(message)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _channel_payload(channel: NotificationChannel, payload: dict[str, Any]) -> dict[str, Any]:
    if channel.kind == "webhook":
        return payload
    alert = payload["alert"]
    text = (
        f"NetWatch {alert['severity']} {payload['event']}: {alert['reference']} "
        f"({alert['category']}, {alert['status']}, occurrences={alert['occurrences']})"
    )
    if "target" in alert:
        target = (
            str(alert["target"]).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        )
        text = f"{text} target={target}"
    return {"text": text}


def _send_once(channel: NotificationChannel, payload: dict[str, Any]) -> None:
    body = json.dumps(
        _channel_payload(channel, payload),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        channel.url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "NetWatch/1.6",
        },
        method="POST",
    )
    try:
        with _open_without_redirects(
            request, timeout=NOTIFICATION_TIMEOUT_SECONDS
        ) as response:  # nosec B310
            response_status = getattr(response, "status", None)
            status = int(response_status if response_status is not None else response.getcode())
            content = read_bounded_response(
                response,
                max_bytes=NOTIFICATION_RESPONSE_MAX_BYTES,
                timeout=NOTIFICATION_TIMEOUT_SECONDS,
                deadline=getattr(response, "_netwatch_delivery_deadline", None),
            )
    except NotificationConfigurationError:
        raise _DeliveryFailure(retryable=False) from None
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        exc.close()
        raise _DeliveryFailure(
            retryable=status == 429 or status >= 500,
            status_code=status,
        ) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise _DeliveryFailure(retryable=True) from None
    if not 200 <= status < 300:
        raise _DeliveryFailure(
            retryable=status == 429 or status >= 500,
            status_code=status,
        )
    if len(content) > NOTIFICATION_RESPONSE_MAX_BYTES:
        raise _DeliveryFailure(retryable=False, status_code=status)


def _deliver(channel: NotificationChannel, payload: dict[str, Any]) -> ChannelNotificationResult:
    attempts = 0
    for retry in range(NOTIFICATION_MAX_RETRIES + 1):
        attempts += 1
        try:
            _send_once(channel, payload)
        except _DeliveryFailure as exc:
            if not exc.retryable or retry >= NOTIFICATION_MAX_RETRIES:
                _record_channel_failure(channel.kind)
                LOGGER.warning(
                    "notification_delivery_failed kind=%s attempts=%s status=%s",
                    channel.kind,
                    attempts,
                    exc.status_code or "transport",
                )
                return ChannelNotificationResult(channel.kind, "failed", attempts)
            time.sleep(_BACKOFF_BASE_SECONDS * (2**retry))
            continue
        _record_channel_success(channel.kind)
        return ChannelNotificationResult(channel.kind, "delivered", attempts)
    _record_channel_failure(channel.kind)  # pragma: no cover - loop always returns
    return ChannelNotificationResult(channel.kind, "failed", attempts)


def deliver_stored_notification(kind: str, payload: dict[str, Any]) -> ChannelNotificationResult:
    """Bypass RAM debounce only for DB-deduped, channel-scoped events."""
    for channel in notification_channels():
        if channel.kind == kind:
            if not channel.enabled:
                return ChannelNotificationResult(channel.kind, "disabled")
            if not _circuit_allows(channel.kind):
                return ChannelNotificationResult(channel.kind, "circuit_open")
            return _deliver(channel, payload)
    raise ValueError("Unsupported notification channel.")


def _result_reason(results: tuple[ChannelNotificationResult, ...]) -> str:
    statuses = {result.status for result in results}
    if "delivered" in statuses and "failed" not in statuses:
        return "delivered"
    if "delivered" in statuses:
        return "partial"
    if "failed" in statuses:
        return "failed"
    if statuses == {"debounced", "disabled"} or statuses == {"debounced"}:
        return "debounced"
    if "circuit_open" in statuses:
        return "circuit_open"
    if "below_minimum_severity" in statuses:
        return "below_minimum_severity"
    return "disabled"


def send_alert_notification(alert: dict[str, Any]) -> NotificationResult:
    """Send an alert safely; delivery failures are returned and never raised."""
    try:
        channels = notification_channels()
        enabled = tuple(channel for channel in channels if channel.enabled)
        if not enabled:
            results = tuple(
                ChannelNotificationResult(channel.kind, "disabled") for channel in channels
            )
            return NotificationResult("disabled", results)
        if not alert_meets_notification_threshold(alert):
            results = tuple(
                ChannelNotificationResult(
                    channel.kind,
                    "below_minimum_severity" if channel.enabled else "disabled",
                )
                for channel in channels
            )
            return NotificationResult("below_minimum_severity", results)
        if not _claim_debounce(_notification_key(alert)):
            results = tuple(
                ChannelNotificationResult(
                    channel.kind,
                    "debounced" if channel.enabled else "disabled",
                )
                for channel in channels
            )
            return NotificationResult("debounced", results)

        payload = build_alert_notification_payload(alert)
        deliveries: list[ChannelNotificationResult] = []
        for channel in channels:
            if not channel.enabled:
                deliveries.append(ChannelNotificationResult(channel.kind, "disabled"))
            elif not _circuit_allows(channel.kind):
                deliveries.append(ChannelNotificationResult(channel.kind, "circuit_open"))
            else:
                deliveries.append(_deliver(channel, payload))
        results = tuple(deliveries)
        return NotificationResult(_result_reason(results), results)
    except Exception:
        LOGGER.error("notification_delivery_failed_safely reason=internal_error")
        return NotificationResult(
            "internal_error",
            (
                ChannelNotificationResult("webhook", "failed"),
                ChannelNotificationResult("slack", "failed"),
            ),
        )


def _notification_worker() -> None:
    while True:
        alert = _notification_queue.get()
        try:
            send_alert_notification(alert)
        finally:
            _notification_queue.task_done()


def _ensure_notification_workers() -> None:
    global _workers_started
    with _worker_lock:
        if _workers_started:
            return
        for index in range(2):
            worker = threading.Thread(
                target=_notification_worker,
                name=f"netwatch-notification-delivery-{index + 1}",
                daemon=True,
            )
            worker.start()
        _workers_started = True


def enqueue_alert_notification(alert: dict[str, Any]) -> bool:
    """Queue notification delivery without delaying the alert database transaction."""
    if not notifications_enabled() or not alert_meets_notification_threshold(alert):
        return False
    _ensure_notification_workers()
    try:
        _notification_queue.put_nowait(dict(alert))
    except queue.Full:
        LOGGER.warning("notification_queue_full delivery_dropped=true")
        return False
    return True


def _reset_notification_state_for_tests() -> None:
    """Reset bounded process state for deterministic unit tests."""
    with _state_lock:
        _debounce_state.clear()
        for state in _circuit_state.values():
            state.consecutive_failures = 0
            state.open_until = 0.0


def _wait_for_notification_queue_for_tests() -> None:
    _notification_queue.join()
