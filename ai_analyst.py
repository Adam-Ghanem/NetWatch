from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True)
class AnalystAssessment:
    risk: str
    confidence: str
    summary: str
    evidence: tuple[str, ...]
    recommended_action: str

    def as_dict(self) -> dict[str, object]:
        return {
            "risk": self.risk,
            "confidence": self.confidence,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "recommended_action": self.recommended_action,
        }


def assess_asset(
    asset: Mapping[str, object], findings: Sequence[Mapping[str, object]] = ()
) -> AnalystAssessment:
    """Produce a deterministic analyst assessment; no network/model calls are made here."""
    fingerprint = asset.get("fingerprint")
    fp = fingerprint if isinstance(fingerprint, Mapping) else {}
    platform = str(fp.get("platform", "Unknown"))
    confidence = str(fp.get("confidence", "Low"))
    items = list(findings)
    severities = {str(item.get("severity", "low")).lower() for item in items}

    if "critical" in severities:
        risk = "Critical"
    elif "high" in severities:
        risk = "High"
    elif "medium" in severities:
        risk = "Medium"
    elif items:
        risk = "Low"
    else:
        risk = "Informational"

    evidence = tuple(
        str(item.get("kind", item.get("type", "behavior change"))) for item in items[:8]
    )
    if not items:
        summary = f"No behavioral findings were supplied for this {platform} asset."
        action = "Continue monitoring and establish a baseline."
    else:
        summary = (
            f"Observed {len(items)} behavioral finding(s) on a {platform} asset; "
            "review the supplied evidence before taking action."
        )
        action = "Validate whether the observed changes were intentional before remediation."

    return AnalystAssessment(risk, confidence, summary, evidence, action)
