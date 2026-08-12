"""Enterprise deployment capability and readiness reporting."""

from __future__ import annotations

import os
from typing import Any

from enterprise_backends import probe_enterprise_backends

ENTERPRISE_MODES = {"single_tenant", "compatibility", "shared_service"}
SUPPORTED_DATABASE_BACKENDS = {"sqlite", "postgresql"}
SUPPORTED_COORDINATION_BACKENDS = {"local", "redis"}
SUPPORTED_OBJECT_BACKENDS = {"local", "s3"}


def _value(name: str, default: str) -> str:
    return os.getenv(name, default).strip().lower() or default


def enterprise_mode() -> str:
    mode = _value("NETWATCH_ENTERPRISE_MODE", "single_tenant")
    return mode if mode in ENTERPRISE_MODES else "single_tenant"


def backend_configuration() -> dict[str, str]:
    return {
        "database": _value("NETWATCH_DATABASE_BACKEND", "sqlite"),
        "coordination": _value("NETWATCH_COORDINATION_BACKEND", "local"),
        "object_storage": _value("NETWATCH_OBJECT_STORAGE_BACKEND", "local"),
        "event_sink": _value("NETWATCH_EVENT_SINK", "local_outbox"),
    }


def _backend_valid(configuration: dict[str, str]) -> bool:
    return (
        configuration["database"] in SUPPORTED_DATABASE_BACKENDS
        and configuration["coordination"] in SUPPORTED_COORDINATION_BACKENDS
        and configuration["object_storage"] in SUPPORTED_OBJECT_BACKENDS
        and configuration["event_sink"] in {"local_outbox", "https", "pubsub"}
    )


def capability_status() -> dict[str, Any]:
    mode = enterprise_mode()
    configuration = backend_configuration()
    configured = _backend_valid(configuration)
    shared_backends_selected = (
        configuration["database"] == "postgresql"
        and configuration["coordination"] == "redis"
        and configuration["object_storage"] == "s3"
        and configuration["event_sink"] in {"https", "pubsub"}
    )
    backend_probes = probe_enterprise_backends()
    shared_service_ready = mode == "shared_service" and shared_backends_selected
    blockers: list[str] = []
    if not configured:
        blockers.append("backend_configuration_invalid")
    if mode == "shared_service" and not shared_backends_selected:
        blockers.append("shared_service_requires_postgresql_redis_s3_and_external_event_sink")
    if mode == "shared_service":
        blockers.extend(backend_probes["blockers"])
        blockers.append("enterprise_adapters_require_contract_and_migration_validation")
        shared_service_ready = False
    return {
        "mode": mode,
        "database": configuration["database"],
        "coordination": configuration["coordination"],
        "object_storage": configuration["object_storage"],
        "event_sink": configuration["event_sink"],
        "local_single_instance_safe": mode in {"single_tenant", "compatibility"},
        "shared_service_ready": shared_service_ready,
        "active_active_supported": False,
        "configuration_valid": configured,
        "blockers": blockers,
        "backend_probes": backend_probes,
    }


def enterprise_readiness() -> dict[str, Any]:
    status = capability_status()
    ready = status["configuration_valid"] and not status["blockers"]
    if status["mode"] == "shared_service":
        ready = False
    return {
        "status": "ready" if ready else "not_ready",
        "migration_required": status["mode"] == "shared_service",
        "safe_to_run_current_process": status["mode"] in {"single_tenant", "compatibility"},
        "capabilities": status,
    }
