from __future__ import annotations

import os
from typing import Any

TRACK_A_GATES = (
    "target_environment_approval",
    "off_host_backup_rotation",
    "managed_key_recovery",
    "representative_load_evidence",
    "security_assessment_retest",
    "accountable_owner_signoff",
)
TRACK_B_GATES = (
    "postgresql_tenant_isolation",
    "distributed_worker_failure_tests",
    "staging_scale_evidence",
    "shared_service_recovery_drill",
    "supply_chain_promotion_evidence",
    "accountable_owner_signoff",
)


def _truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes"}


def _reference(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value[:160] if value else None


def _track_status(
    *,
    name: str,
    gates: tuple[str, ...],
    verified_env: str,
    reference_env: str,
) -> dict[str, Any]:
    verified = _truthy(verified_env)
    reference = _reference(reference_env)
    if verified and reference:
        return {
            "track": name,
            "status": "operator_declared_ready",
            "score": 100,
            "evidence_reference": reference,
            "gates": {gate: "declared_complete" for gate in gates},
            "warning": (
                "This is an operator declaration; retain the underlying evidence "
                "package and approval record."
            ),
        }
    return {
        "track": name,
        "status": "evidence_pending",
        "score": 0,
        "evidence_reference": reference,
        "gates": {gate: "pending" for gate in gates},
        "warning": (
            "Readiness cannot be inferred from configuration, tests, or a "
            "Kubernetes manifest alone."
        ),
    }


def readiness_center() -> dict[str, Any]:
    mode = os.getenv("NETWATCH_ENTERPRISE_MODE", "single_tenant").strip().lower()
    track_a = _track_status(
        name="A_single_tenant",
        gates=TRACK_A_GATES,
        verified_env="NETWATCH_TRACK_A_EVIDENCE_VERIFIED",
        reference_env="NETWATCH_TRACK_A_EVIDENCE_REFERENCE",
    )
    track_b = _track_status(
        name="B_shared_service",
        gates=TRACK_B_GATES,
        verified_env="NETWATCH_TRACK_B_EVIDENCE_VERIFIED",
        reference_env="NETWATCH_TRACK_B_EVIDENCE_REFERENCE",
    )
    active = track_b if mode == "shared_service" else track_a
    blockers = [gate for gate, status in active["gates"].items() if status == "pending"]
    return {
        "operating_mode": mode,
        "active_track": active["track"],
        "status": active["status"],
        "score": active["score"],
        "evidence_reference": active["evidence_reference"],
        "blockers": blockers,
        "track_a": track_a,
        "track_b": track_b,
        "claim_boundary": (
            "100 means an accountable operator declared the complete evidence "
            "package; it is not inferred automatically."
        ),
    }
