from __future__ import annotations


def asset_confidence(*, fingerprint_score: int, evidence_count: int, behavior_findings: int) -> int:
    """Return a bounded confidence indicator for an asset snapshot."""
    score = max(0, min(100, int(fingerprint_score)))
    evidence_bonus = min(20, max(0, int(evidence_count)) * 4)
    instability_penalty = min(20, max(0, int(behavior_findings)) * 2)
    return max(0, min(100, score + evidence_bonus - instability_penalty))
