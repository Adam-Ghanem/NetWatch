from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import enterprise_auth

ISSUER = "https://identity.example.com/tenant"
AUDIENCE = "netwatch-production"


@pytest.fixture
def oidc_environment(monkeypatch):
    values = {
        "NETWATCH_OIDC_ENABLED": "true",
        "NETWATCH_OIDC_ISSUER": ISSUER,
        "NETWATCH_OIDC_AUDIENCE": AUDIENCE,
        "NETWATCH_OIDC_JWKS_URL": f"{ISSUER}/keys",
        "NETWATCH_OIDC_GROUPS_CLAIM": "groups",
        "NETWATCH_OIDC_ADMIN_GROUPS": "netwatch-admins",
        "NETWATCH_OIDC_OPERATOR_GROUPS": "netwatch-operators",
        "NETWATCH_OIDC_VIEWER_GROUPS": "netwatch-viewers",
        "NETWATCH_OIDC_ALGORITHMS": "RS256",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    enterprise_auth.reset_jwks_client_cache()


@pytest.fixture
def signing_key(monkeypatch, oidc_environment):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = SimpleNamespace(
        get_signing_key_from_jwt=lambda _: SimpleNamespace(key=private_key.public_key())
    )
    monkeypatch.setattr(enterprise_auth, "_jwks_client", lambda _: client)
    return private_key


def _token(private_key, **updates) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "employee-1042",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "groups": ["netwatch-viewers"],
    }
    claims.update(updates)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "company-key-1"})


def test_verified_token_maps_exact_company_group_to_role(signing_key):
    token = _token(signing_key, groups=["netwatch-admins", "unrelated"])

    identity = enterprise_auth.verify_oidc_token(token)

    assert identity.subject == "employee-1042"
    assert identity.role == "admin"


@pytest.mark.parametrize(
    "claim_update",
    [
        {"aud": "another-service"},
        {"iss": "https://identity.example.com/another-tenant"},
        {"exp": datetime.now(timezone.utc) - timedelta(minutes=5)},
    ],
)
def test_wrong_audience_issuer_or_expiry_is_rejected(signing_key, claim_update):
    token = _token(signing_key, **claim_update)

    with pytest.raises(enterprise_auth.OIDCAuthenticationError):
        enterprise_auth.verify_oidc_token(token)


def test_unmapped_group_is_denied_after_authentication(signing_key):
    token = _token(signing_key, groups=["unrelated"])

    with pytest.raises(enterprise_auth.OIDCAuthorizationError):
        enterprise_auth.verify_oidc_token(token)


def test_oidc_subject_must_be_a_canonical_single_token(signing_key):
    token = _token(signing_key, sub="employee 1042")

    with pytest.raises(enterprise_auth.OIDCAuthenticationError, match="subject"):
        enterprise_auth.verify_oidc_token(token)


def test_attacker_controlled_jwks_header_is_rejected_before_lookup(signing_key):
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "employee-1042",
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "groups": ["netwatch-admins"],
        },
        signing_key,
        algorithm="RS256",
        headers={"kid": "company-key-1", "jku": "https://attacker.example/jwks"},
    )

    with pytest.raises(enterprise_auth.OIDCAuthenticationError, match="key references"):
        enterprise_auth.verify_oidc_token(token)


def test_oidc_configuration_requires_https_and_role_mapping(monkeypatch, oidc_environment):
    monkeypatch.setenv("NETWATCH_OIDC_ISSUER", "http://identity.example.com")
    with pytest.raises(enterprise_auth.OIDCConfigurationError, match="HTTPS"):
        enterprise_auth.oidc_settings()

    monkeypatch.setenv("NETWATCH_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("NETWATCH_OIDC_ADMIN_GROUPS", "")
    monkeypatch.setenv("NETWATCH_OIDC_OPERATOR_GROUPS", "")
    monkeypatch.setenv("NETWATCH_OIDC_VIEWER_GROUPS", "")
    with pytest.raises(enterprise_auth.OIDCConfigurationError, match="mapping"):
        enterprise_auth.oidc_settings()


def test_oidc_configuration_rejects_ambiguous_role_groups(monkeypatch, oidc_environment):
    monkeypatch.setenv("NETWATCH_OIDC_OPERATOR_GROUPS", "netwatch-admins")

    with pytest.raises(enterprise_auth.OIDCConfigurationError, match="more than one role"):
        enterprise_auth.oidc_settings()


def test_oidc_enable_flag_rejects_ambiguous_values(monkeypatch):
    monkeypatch.setenv("NETWATCH_OIDC_ENABLED", "treu")

    assert enterprise_auth.oidc_configuration_status() == (False, "invalid")
    with pytest.raises(enterprise_auth.OIDCConfigurationError, match="true or false"):
        enterprise_auth.oidc_enabled()


def test_oidc_urls_reject_query_credentials_and_preserve_exact_issuer(
    monkeypatch, oidc_environment
):
    monkeypatch.setenv("NETWATCH_OIDC_ISSUER", f"{ISSUER}/")
    assert enterprise_auth.oidc_settings().issuer == f"{ISSUER}/"

    monkeypatch.setenv("NETWATCH_OIDC_JWKS_URL", f"{ISSUER}/keys?token=unexpected")
    with pytest.raises(enterprise_auth.OIDCConfigurationError, match="query"):
        enterprise_auth.oidc_settings()

    monkeypatch.setenv("NETWATCH_OIDC_JWKS_URL", "https://[invalid")
    with pytest.raises(enterprise_auth.OIDCConfigurationError, match="valid URL"):
        enterprise_auth.oidc_settings()


def test_jwks_client_disables_individual_key_cache(monkeypatch, oidc_environment):
    captured: dict[str, object] = {}
    sentinel = object()

    def fake_client(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(enterprise_auth, "PyJWKClient", fake_client)
    enterprise_auth.reset_jwks_client_cache()

    client = enterprise_auth._jwks_client(enterprise_auth.oidc_settings())

    assert client is sentinel
    assert captured["cache_keys"] is False
    assert captured["cache_jwk_set"] is True
    assert captured["lifespan"] == 300
    assert captured["timeout"] == 5


def test_token_lifetime_is_bounded_by_application_policy(signing_key):
    now = datetime.now(timezone.utc)
    token = _token(
        signing_key,
        iat=now - timedelta(hours=2),
        exp=now + timedelta(minutes=5),
    )

    with pytest.raises(enterprise_auth.OIDCAuthenticationError, match="lifetime"):
        enterprise_auth.verify_oidc_token(token)


@pytest.mark.parametrize("invalid_iat", [float("inf"), {"unexpected": True}])
def test_invalid_numeric_dates_are_normalized_to_authentication_failures(signing_key, invalid_iat):
    token = _token(signing_key, iat=invalid_iat)

    with pytest.raises(enterprise_auth.OIDCAuthenticationError):
        enterprise_auth.verify_oidc_token(token)
