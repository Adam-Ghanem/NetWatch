from __future__ import annotations

import pytest

from ai_client import AIConfigurationError, analyze_with_ai


def test_legacy_raw_evidence_adapter_fails_closed_without_provider_call(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai-key-that-must-never-be-used")
    sensitive_asset = {
        "ip_address": "192.0.2.25",
        "hostname": "private-workstation",
        "owner": "Confidential Owner",
    }
    sensitive_findings = [{"details": "private incident details"}]

    with pytest.raises(
        AIConfigurationError, match="legacy raw-evidence AI adapter is disabled"
    ):
        analyze_with_ai(asset=sensitive_asset, findings=sensitive_findings)

    # The failure message is static and never reflects supplied evidence or keys.
    with pytest.raises(AIConfigurationError) as caught:
        analyze_with_ai(
            asset=sensitive_asset,
            findings=sensitive_findings,
            model="test-model",
        )
    message = str(caught.value)
    assert "192.0.2.25" not in message
    assert "private-workstation" not in message
    assert "Confidential Owner" not in message
    assert "private incident details" not in message
    assert "test-openai-key" not in message


def test_legacy_adapter_keeps_signature_but_does_not_require_credentials(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(AIConfigurationError, match="de-identified evidence snapshot"):
        analyze_with_ai(asset={"status": "observed"})
