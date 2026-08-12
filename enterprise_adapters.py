"""Optional shared-service adapters for the ABC enterprise target.

Adapters are lazy and never selected by the default single-tenant/compatibility modes.
They require explicit configuration, installed optional dependencies, and a readiness gate.
"""

from __future__ import annotations

import json
import os
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from notifications import validate_notification_url


class EnterpriseAdapterUnavailable(RuntimeError):
    """Raised when a shared-service adapter is not configured or installed."""


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise EnterpriseAdapterUnavailable(f"{name} is required for the selected adapter.")
    return value


@dataclass(frozen=True)
class PostgresAdapter:
    url: str

    @contextmanager
    def transaction(self) -> Iterator[Any]:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise EnterpriseAdapterUnavailable("psycopg is not installed.") from exc
        connection = psycopg.connect(self.url, connect_timeout=5)
        try:
            with connection.transaction():
                yield connection
        finally:
            connection.close()

    def readiness_sql(self) -> bool:
        with self.transaction() as connection:
            connection.execute("SELECT 1")
        return True


@dataclass(frozen=True)
class RedisCoordinator:
    url: str

    def _client(self) -> Any:
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise EnterpriseAdapterUnavailable("redis is not installed.") from exc
        return redis.Redis.from_url(self.url, socket_connect_timeout=5, socket_timeout=5)

    def acquire_lease(self, key: str, owner: str, ttl_seconds: int = 300) -> bool:
        if not key or not owner:
            raise ValueError("Lease key and owner are required.")
        safe_ttl = max(30, min(int(ttl_seconds), 3_600))
        return bool(self._client().set(key, owner, nx=True, ex=safe_ttl))

    def release_lease(self, key: str, owner: str) -> bool:
        script = (
            "if redis.call('get', KEYS[1]) == ARGV[1] "
            "then return redis.call('del', KEYS[1]) else return 0 end"
        )
        return bool(self._client().eval(script, 1, key, owner))

    def readiness_ping(self) -> bool:
        return bool(self._client().ping())


@dataclass(frozen=True)
class S3ObjectStore:
    bucket: str
    prefix: str = "netwatch/"

    def _client(self) -> Any:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise EnterpriseAdapterUnavailable("boto3 is not installed.") from exc
        endpoint = os.getenv("NETWATCH_S3_ENDPOINT", "").strip() or None
        return boto3.client("s3", endpoint_url=endpoint)

    def put_bytes(self, key: str, content: bytes, content_type: str) -> str:
        safe_key = "/".join(
            part for part in str(key).split("/") if part and part not in {".", ".."}
        )
        if not safe_key or len(safe_key) > 512:
            raise ValueError("Object key is invalid or too long.")
        if len(content) > 100 * 1024 * 1024:
            raise ValueError("Object exceeds the bounded upload size.")
        object_key = f"{self.prefix}{safe_key}"
        self._client().put_object(
            Bucket=self.bucket,
            Key=object_key,
            Body=content,
            ContentType=str(content_type)[:120],
            ServerSideEncryption="AES256",
        )
        return object_key

    def readiness_head(self) -> bool:
        self._client().head_bucket(Bucket=self.bucket)
        return True


@dataclass(frozen=True)
class HttpsEventSink:
    url: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "url", validate_notification_url(self.url, field_name="Event sink URL")
        )

    def publish(self, event: dict[str, Any]) -> None:
        body = json.dumps(event, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        if len(body) > 256 * 1024:
            raise ValueError("Event exceeds the bounded payload size.")
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "NetWatch-enterprise/1"},
            method="POST",
        )
        opener = urllib.request.build_opener(_NoRedirectHandler())
        with opener.open(request, timeout=5) as response:  # nosec B310
            if not 200 <= int(response.getcode()) < 300:
                raise EnterpriseAdapterUnavailable("Event sink returned a non-success status.")
            response.read(64 * 1024 + 1)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_enterprise_adapters() -> dict[str, Any]:
    """Build configured adapters without making network calls."""
    database = os.getenv("NETWATCH_DATABASE_BACKEND", "sqlite").strip().lower()
    coordination = os.getenv("NETWATCH_COORDINATION_BACKEND", "local").strip().lower()
    objects = os.getenv("NETWATCH_OBJECT_STORAGE_BACKEND", "local").strip().lower()
    event_sink = os.getenv("NETWATCH_EVENT_SINK", "local_outbox").strip().lower()
    adapters: dict[str, Any] = {}
    if database == "postgresql":
        adapters["database"] = PostgresAdapter(_required_env("NETWATCH_DATABASE_URL"))
    if coordination == "redis":
        adapters["coordination"] = RedisCoordinator(_required_env("NETWATCH_REDIS_URL"))
    if objects == "s3":
        adapters["object_storage"] = S3ObjectStore(_required_env("NETWATCH_S3_BUCKET"))
    if event_sink == "https":
        adapters["event_sink"] = HttpsEventSink(_required_env("NETWATCH_EVENT_SINK_URL"))
    return adapters
