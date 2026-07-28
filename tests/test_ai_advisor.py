from __future__ import annotations

import hashlib
import hmac
import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import ai_advisor
from ai_advisor import (
    AIProviderError,
    IntelligenceBrief,
    _NoRedirectHandler,
    build_deidentified_snapshot,
    build_openai_request_payload,
    parse_openai_response,
    request_intelligence_brief,
    safety_configuration_is_usable,
    safety_identifier,
    snapshot_hash,
)


def _snapshot() -> dict:
    return build_deidentified_snapshot(
        inventory_rows=[
            {
                "ip_address": "192.168.10.25",
                "owner": "Sensitive Owner",
                "department": "Finance",
                "location": "Private HQ",
                "notes": "Never share this note",
                "hostname": "Adam-iPhone",
                "mac_address": "00:1C:B3:00:00:01",
                "manufacturer": "Apple, Inc.",
                "device_name": "Adam-iPhone",
                "device_family": "Apple iPhone",
                "status": "Seen",
                "criticality": "Critical",
                "exposure_level": "High",
                "exposure_score": 14,
            }
        ],
        port_rows=[
            {
                "IP Address": "192.168.10.25",
                "Port": 445,
                "Service": "untrusted service label",
                "Risk": "High",
            }
        ],
        alert_rows=[
            {
                "id": 7,
                "target": "192.168.10.25",
                "details": "Secret raw evidence",
                "assigned_to": "Sensitive Owner",
                "severity": "High",
                "status": "open",
                "category": "asset_not_observed",
                "occurrence_count": 3,
                "overdue": True,
            }
        ],
        change_rows=[
            {
                "ip_address": "192.168.10.25",
                "details": "Raw change detail",
                "event_type": "not_observed",
            }
        ],
        operation_metrics={
            "open": 1,
            "acknowledged": 0,
            "overdue": 1,
            "critical_unresolved": 0,
            "policies": 2,
            "enabled_policies": 1,
            "active_maintenance": 0,
        },
    )


def _brief_json() -> str:
    return json.dumps(
        {
            "risk_level": "High",
            "executive_summary": "Saved evidence requires prioritized defensive validation.",
            "key_observations": ["Case case-7 is overdue and has repeated observations."],
            "recommended_actions": [
                {
                    "priority": "Immediate",
                    "title": "Validate the overdue case",
                    "rationale": "Repeated evidence warrants an owner-led review.",
                    "validation": "Confirm service need and document the result in case-7.",
                }
            ],
            "limitations": ["The snapshot contains observations, not proof of compromise."],
        }
    )


def test_deidentified_snapshot_excludes_sensitive_inventory_fields():
    snapshot = _snapshot()
    encoded = json.dumps(snapshot, sort_keys=True)

    for sensitive in (
        "192.168.10.25",
        "Sensitive Owner",
        "Finance",
        "Private HQ",
        "Never share this note",
        "Adam-iPhone",
        "00:1C:B3:00:00:01",
        "Apple, Inc.",
        "Apple iPhone",
        "Secret raw evidence",
        "Raw change detail",
        "untrusted service label",
    ):
        assert sensitive not in encoded

    assert snapshot["service_exposure"]["services"][0]["service"] == "SMB"
    assert snapshot["cases"]["top_cases"][0]["reference"] == "case-7"
    assert len(snapshot_hash(snapshot)) == 64


def test_openai_request_is_bounded_structured_and_stateless():
    snapshot = _snapshot()
    payload = build_openai_request_payload(
        snapshot,
        model="gpt-test-model",
        safety_id="nw_test_identifier",
        max_output_tokens=900,
    )
    encoded = json.dumps(payload)

    assert payload["store"] is False
    assert payload["max_output_tokens"] == 900
    assert payload["safety_identifier"] == "nw_test_identifier"
    assert payload["text"]["format"]["type"] == "json_schema"
    assert payload["text"]["format"]["strict"] is True
    assert "tools" not in payload
    assert "192.168.10.25" not in encoded
    assert "OPENAI_API_KEY" not in encoded


def test_safety_identifier_uses_an_independent_opaque_identity():
    secret = "test-independent-safety-secret-with-enough-characters"
    subject = "deployment_subject_12345"
    provider_key = "test-openai-project-key-with-enough-characters"
    first = safety_identifier(safety_secret=secret, subject_id=subject)
    second = safety_identifier(safety_secret=secret, subject_id=subject)
    different = safety_identifier(
        safety_secret=secret,
        subject_id="deployment_subject_67890",
    )

    assert first == second
    assert first != different
    assert subject not in first
    assert secret not in first
    provider_keyed_candidates = {
        "nw_"
        + hmac.new(
            provider_key.encode(),
            f"{role}:192.168.50.{host}".encode(),
            hashlib.sha256,
        ).hexdigest()[:48]
        for role in ("viewer", "operator", "admin")
        for host in range(1, 255)
    }
    assert first not in provider_keyed_candidates


def test_safety_configuration_fails_closed_without_key_separation():
    provider_key = "test-openai-project-key-with-enough-characters"
    safety_secret = "test-independent-safety-secret-with-enough-characters"
    subject = "deployment_subject_12345"

    assert safety_configuration_is_usable(
        api_key=provider_key,
        safety_secret=safety_secret,
        subject_id=subject,
    )
    assert not safety_configuration_is_usable(
        api_key=provider_key,
        safety_secret=provider_key,
        subject_id=subject,
    )
    assert not safety_configuration_is_usable(
        api_key=provider_key,
        safety_secret="",
        subject_id=subject,
    )
    assert not safety_configuration_is_usable(
        api_key=provider_key,
        safety_secret=safety_secret,
        subject_id="operator:192.0.2.10",
    )
    assert not safety_configuration_is_usable(
        api_key=provider_key,
        safety_secret=safety_secret,
        subject_id="replace-with-an-opaque-random-subject",
    )


def test_structured_provider_response_is_validated():
    result = parse_openai_response(
        {
            "id": "resp_safe_123",
            "output": [
                {"type": "message", "content": [{"type": "output_text", "text": _brief_json()}]}
            ],
            "usage": {"input_tokens": 321, "output_tokens": 123},
        }
    )

    assert isinstance(result.brief, IntelligenceBrief)
    assert result.brief.risk_level == "High"
    assert result.provider_request_id == "resp_safe_123"
    assert result.input_tokens == 321
    assert result.output_tokens == 123


def test_provider_call_keeps_key_in_authorization_header_only():
    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _: int) -> bytes:
            return json.dumps(
                {
                    "id": "resp_safe_456",
                    "output_text": _brief_json(),
                    "usage": {"input_tokens": 20, "output_tokens": 10},
                }
            ).encode()

    def opener(request, timeout):
        captured["authorization"] = request.get_header("Authorization")
        captured["body"] = request.data
        captured["timeout"] = timeout
        return FakeResponse()

    key = "test-openai-project-key-with-enough-characters"
    safety_secret = "test-independent-safety-secret-with-enough-characters"
    subject = "deployment_subject_12345"
    safety_id = safety_identifier(safety_secret=safety_secret, subject_id=subject)
    result = request_intelligence_brief(
        _snapshot(),
        api_key=key,
        safety_id=safety_id,
        model="gpt-test-model",
        opener=opener,
    )

    assert result.brief.risk_level == "High"
    assert captured["authorization"] == f"Bearer {key}"
    body = captured["body"]
    assert isinstance(body, bytes)
    assert key.encode() not in body
    assert safety_secret.encode() not in body
    assert subject.encode() not in body


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_provider_redirects_never_create_a_follow_up_request(status):
    handler = _NoRedirectHandler()
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=b"{}",
        headers={"Authorization": "Bearer dummy-provider-key"},
        method="POST",
    )

    redirected = getattr(handler, "redirect_request")(
        request,
        None,
        status,
        "redirect",
        {},
        "https://redirect.invalid/capture",
    )

    assert redirected is None


def test_default_provider_transport_does_not_forward_credentials_on_redirect(monkeypatch):
    class CaptureHandler(BaseHTTPRequestHandler):
        calls = 0

        def do_POST(self):
            CaptureHandler.calls += 1
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            return

    capture_server = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
    capture_thread = threading.Thread(target=capture_server.serve_forever, daemon=True)
    capture_thread.start()

    destination = f"http://127.0.0.1:{capture_server.server_port}/capture"

    class RedirectHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", destination)
            self.end_headers()

        def log_message(self, *_):
            return

    redirect_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    redirect_thread = threading.Thread(target=redirect_server.serve_forever, daemon=True)
    redirect_thread.start()
    monkeypatch.setattr(
        ai_advisor,
        "OPENAI_RESPONSES_URL",
        f"http://127.0.0.1:{redirect_server.server_port}/responses",
    )

    try:
        with pytest.raises(AIProviderError) as exc_info:
            request_intelligence_brief(
                _snapshot(),
                api_key="dummy-provider-key-with-enough-characters",
                safety_id="nw_test_identifier",
            )
    finally:
        redirect_server.shutdown()
        redirect_server.server_close()
        capture_server.shutdown()
        capture_server.server_close()
        redirect_thread.join(timeout=2)
        capture_thread.join(timeout=2)

    assert exc_info.value.code == "provider_redirect_blocked"
    assert CaptureHandler.calls == 0


def test_invalid_provider_output_fails_closed():
    with pytest.raises(AIProviderError, match="invalid structured brief") as exc_info:
        parse_openai_response({"output_text": '{"risk_level":"High"}'})

    assert exc_info.value.code == "invalid_provider_response"
    assert exc_info.value.http_status == 502


def test_structured_provider_strings_are_individually_bounded():
    payload = json.loads(_brief_json())
    payload["key_observations"] = ["x" * 401]

    with pytest.raises(AIProviderError, match="invalid structured brief"):
        parse_openai_response({"output_text": json.dumps(payload)})
