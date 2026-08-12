"""Fail-closed configuration probes for optional enterprise service adapters.

The probes intentionally avoid opening network connections during import or request handling.
Deployment health checks can call ``probe_enterprise_backends`` before enabling shared-service mode.
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BackendProbe:
    name: str
    selected: bool
    configured: bool
    dependency_present: bool
    ready: bool
    blockers: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "selected": self.selected,
            "configured": self.configured,
            "dependency_present": self.dependency_present,
            "ready": self.ready,
            "blockers": list(self.blockers),
        }


def _env(name: str) -> str:
    return os.getenv(name, "").strip()


def _dependency(name: str) -> bool:
    return importlib.util.find_spec(name) is not None


def probe_enterprise_backends() -> dict[str, Any]:
    database = _env("NETWATCH_DATABASE_BACKEND").lower() or "sqlite"
    coordination = _env("NETWATCH_COORDINATION_BACKEND").lower() or "local"
    object_storage = _env("NETWATCH_OBJECT_STORAGE_BACKEND").lower() or "local"
    event_sink = _env("NETWATCH_EVENT_SINK").lower() or "local_outbox"

    postgres = BackendProbe(
        name="postgresql",
        selected=database == "postgresql",
        configured=bool(_env("NETWATCH_DATABASE_URL")),
        dependency_present=_dependency("psycopg"),
        ready=(
            database != "postgresql"
            or (bool(_env("NETWATCH_DATABASE_URL")) and _dependency("psycopg"))
        ),
        blockers=tuple(
            item
            for item, missing in (
                ("NETWATCH_DATABASE_URL_missing", not bool(_env("NETWATCH_DATABASE_URL"))),
                ("psycopg_not_installed", not _dependency("psycopg")),
            )
            if database == "postgresql" and missing
        ),
    )
    redis = BackendProbe(
        name="redis",
        selected=coordination == "redis",
        configured=bool(_env("NETWATCH_REDIS_URL")),
        dependency_present=_dependency("redis"),
        ready=(
            coordination != "redis" or (bool(_env("NETWATCH_REDIS_URL")) and _dependency("redis"))
        ),
        blockers=tuple(
            item
            for item, missing in (
                ("NETWATCH_REDIS_URL_missing", not bool(_env("NETWATCH_REDIS_URL"))),
                ("redis_not_installed", not _dependency("redis")),
            )
            if coordination == "redis" and missing
        ),
    )
    s3 = BackendProbe(
        name="s3",
        selected=object_storage == "s3",
        configured=bool(_env("NETWATCH_S3_BUCKET")),
        dependency_present=_dependency("boto3"),
        ready=(
            object_storage != "s3" or (bool(_env("NETWATCH_S3_BUCKET")) and _dependency("boto3"))
        ),
        blockers=tuple(
            item
            for item, missing in (
                ("NETWATCH_S3_BUCKET_missing", not bool(_env("NETWATCH_S3_BUCKET"))),
                ("boto3_not_installed", not _dependency("boto3")),
            )
            if object_storage == "s3" and missing
        ),
    )
    external_events = event_sink in {"https", "pubsub"}
    events = BackendProbe(
        name="event_sink",
        selected=external_events,
        configured=bool(_env("NETWATCH_EVENT_SINK_URL") or _env("NETWATCH_PUBSUB_TOPIC")),
        dependency_present=True,
        ready=(
            not external_events
            or bool(_env("NETWATCH_EVENT_SINK_URL") or _env("NETWATCH_PUBSUB_TOPIC"))
        ),
        blockers=tuple(
            ["NETWATCH_EVENT_SINK_URL_or_PUBSUB_TOPIC_missing"]
            if external_events
            and not (_env("NETWATCH_EVENT_SINK_URL") or _env("NETWATCH_PUBSUB_TOPIC"))
            else []
        ),
    )
    probes = {probe.name: probe.as_dict() for probe in (postgres, redis, s3, events)}
    blockers = [blocker for probe in (postgres, redis, s3, events) for blocker in probe.blockers]
    return {
        "selected": {
            "database": database,
            "coordination": coordination,
            "object_storage": object_storage,
            "event_sink": event_sink,
        },
        "ready": not blockers,
        "blockers": blockers,
        "probes": probes,
    }
