from asset_confidence import asset_confidence


def test_confidence_is_bounded():
    assert asset_confidence(fingerprint_score=95, evidence_count=20, behavior_findings=0) == 100
    assert asset_confidence(fingerprint_score=5, evidence_count=0, behavior_findings=20) == 0


def test_evidence_raises_and_instability_lowers_confidence():
    base = asset_confidence(fingerprint_score=70, evidence_count=0, behavior_findings=0)
    richer = asset_confidence(fingerprint_score=70, evidence_count=2, behavior_findings=0)
    noisy = asset_confidence(fingerprint_score=70, evidence_count=2, behavior_findings=3)
    assert richer > base
    assert noisy < richer
