"""Fail-closed enterprise identity verification for NetWatch.

NetWatch can remain on local role keys, or a deployment can place it behind an
OIDC-aware reverse proxy that forwards a signed bearer token.  Tokens are
verified against a deployment-controlled JWKS URL and mapped to the existing
Viewer, Operator, and Admin roles through exact group names.
"""

from __future__ import annotations

import math
import os
import re
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError, PyJWKClientError, PyJWTError

_SAFE_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"}
)
_CLAIM_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_CLIENTS: dict[tuple[str, int, int], PyJWKClient] = {}
_CLIENTS_LOCK = threading.Lock()


class OIDCConfigurationError(RuntimeError):
    """The deployment requested OIDC but supplied unsafe or incomplete settings."""


class OIDCAuthenticationError(RuntimeError):
    """The supplied bearer token could not be authenticated."""


class OIDCAuthorizationError(RuntimeError):
    """The authenticated subject has no mapped NetWatch role."""


class OIDCProviderUnavailableError(RuntimeError):
    """The configured identity provider could not be reached safely."""


@dataclass(frozen=True)
class OIDCSettings:
    issuer: str
    audience: str
    jwks_url: str
    groups_claim: str
    admin_groups: frozenset[str]
    operator_groups: frozenset[str]
    viewer_groups: frozenset[str]
    algorithms: tuple[str, ...]
    clock_skew_seconds: int
    max_token_age_seconds: int
    jwks_cache_seconds: int
    jwks_timeout_seconds: int


@dataclass(frozen=True)
class OIDCIdentity:
    subject: str
    role: str


def _strict_env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name, "true" if default else "false").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise OIDCConfigurationError(f"{name} must be true or false.")


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)).strip())
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _csv_set(name: str) -> frozenset[str]:
    values = {
        item.strip()
        for item in os.getenv(name, "").split(",")
        if item.strip() and len(item.strip()) <= 128
    }
    return frozenset(values)


def _https_url(value: str, *, field: str) -> str:
    candidate = value.strip()
    try:
        parsed = urlparse(candidate)
        parsed.port
    except ValueError as exc:
        raise OIDCConfigurationError(f"{field} is not a valid URL.") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or any(character.isspace() or not character.isprintable() for character in candidate)
    ):
        raise OIDCConfigurationError(
            f"{field} must be an HTTPS URL without credentials, query, or fragment."
        )
    return candidate


def oidc_enabled() -> bool:
    return _strict_env_bool("NETWATCH_OIDC_ENABLED", False)


def oidc_settings() -> OIDCSettings:
    """Load and strictly validate the current deployment's OIDC settings."""
    if not oidc_enabled():
        raise OIDCConfigurationError("OIDC authentication is disabled.")

    issuer = _https_url(os.getenv("NETWATCH_OIDC_ISSUER", ""), field="OIDC issuer")
    audience = os.getenv("NETWATCH_OIDC_AUDIENCE", "").strip()
    if not audience or len(audience) > 256 or any(character.isspace() for character in audience):
        raise OIDCConfigurationError("OIDC audience must be a non-empty bounded identifier.")

    jwks_url = _https_url(os.getenv("NETWATCH_OIDC_JWKS_URL", ""), field="OIDC JWKS URL")
    groups_claim = os.getenv("NETWATCH_OIDC_GROUPS_CLAIM", "groups").strip()
    if not _CLAIM_NAME.fullmatch(groups_claim):
        raise OIDCConfigurationError("OIDC groups claim name is invalid.")

    admin_groups = _csv_set("NETWATCH_OIDC_ADMIN_GROUPS")
    operator_groups = _csv_set("NETWATCH_OIDC_OPERATOR_GROUPS")
    viewer_groups = _csv_set("NETWATCH_OIDC_VIEWER_GROUPS")
    if not (admin_groups or operator_groups or viewer_groups):
        raise OIDCConfigurationError("At least one OIDC group-to-role mapping is required.")
    if (
        admin_groups & operator_groups
        or admin_groups & viewer_groups
        or operator_groups & viewer_groups
    ):
        raise OIDCConfigurationError("OIDC groups cannot be mapped to more than one role.")

    requested_algorithms = tuple(
        dict.fromkeys(
            item.strip().upper()
            for item in os.getenv("NETWATCH_OIDC_ALGORITHMS", "RS256").split(",")
            if item.strip()
        )
    )
    if (
        not requested_algorithms
        or len(requested_algorithms) > 4
        or any(item not in _SAFE_ALGORITHMS for item in requested_algorithms)
    ):
        raise OIDCConfigurationError("OIDC signing algorithms are missing or unsupported.")

    return OIDCSettings(
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        groups_claim=groups_claim,
        admin_groups=admin_groups,
        operator_groups=operator_groups,
        viewer_groups=viewer_groups,
        algorithms=requested_algorithms,
        clock_skew_seconds=_bounded_int("NETWATCH_OIDC_CLOCK_SKEW_SECONDS", 30, 0, 120),
        max_token_age_seconds=_bounded_int(
            "NETWATCH_OIDC_MAX_TOKEN_AGE_SECONDS", 3_600, 300, 86_400
        ),
        jwks_cache_seconds=_bounded_int("NETWATCH_OIDC_JWKS_CACHE_SECONDS", 300, 60, 86_400),
        jwks_timeout_seconds=_bounded_int("NETWATCH_OIDC_JWKS_TIMEOUT_SECONDS", 5, 1, 10),
    )


def oidc_configuration_status() -> tuple[bool, str]:
    try:
        if not oidc_enabled():
            return False, "disabled"
        oidc_settings()
    except OIDCConfigurationError:
        return False, "invalid"
    return True, "configured"


def reset_jwks_client_cache() -> None:
    """Drop cached clients after configuration rotation and in isolated tests."""
    with _CLIENTS_LOCK:
        _CLIENTS.clear()


def _jwks_client(settings: OIDCSettings) -> PyJWKClient:
    key = (settings.jwks_url, settings.jwks_cache_seconds, settings.jwks_timeout_seconds)
    with _CLIENTS_LOCK:
        client = _CLIENTS.get(key)
        if client is None:
            client = PyJWKClient(
                settings.jwks_url,
                cache_keys=False,
                cache_jwk_set=True,
                lifespan=settings.jwks_cache_seconds,
                timeout=settings.jwks_timeout_seconds,
            )
            _CLIENTS[key] = client
        return client


def _validated_subject(claims: dict[str, Any]) -> str:
    subject = claims.get("sub")
    if not isinstance(subject, str):
        raise OIDCAuthenticationError("The bearer token subject is invalid.")
    if (
        not subject
        or len(subject) > 160
        or any(character.isspace() or not character.isprintable() for character in subject)
    ):
        raise OIDCAuthenticationError("The bearer token subject is invalid.")
    return subject


def _validated_groups(claims: dict[str, Any], claim_name: str) -> frozenset[str]:
    raw_groups = claims.get(claim_name)
    if not isinstance(raw_groups, (list, tuple)) or len(raw_groups) > 200:
        raise OIDCAuthorizationError("The bearer token has no usable group assignment.")
    groups = {
        item.strip()
        for item in raw_groups
        if isinstance(item, str) and item.strip() and len(item.strip()) <= 128
    }
    return frozenset(groups)


def _finite_numeric_date(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _role_for_groups(groups: frozenset[str], settings: OIDCSettings) -> str:
    if groups & settings.admin_groups:
        return "admin"
    if groups & settings.operator_groups:
        return "operator"
    if groups & settings.viewer_groups:
        return "viewer"
    raise OIDCAuthorizationError("The authenticated user has no mapped NetWatch role.")


def verify_oidc_token(token: str) -> OIDCIdentity:
    """Verify one provider token and return the least-privilege mapped identity."""
    settings = oidc_settings()
    candidate = token.strip()
    if (
        not candidate
        or len(candidate) > 16_384
        or any(character.isspace() for character in candidate)
    ):
        raise OIDCAuthenticationError("The bearer token is malformed.")

    try:
        header = jwt.get_unverified_header(candidate)
    except PyJWTError as exc:
        raise OIDCAuthenticationError("The bearer token header is invalid.") from exc
    algorithm = header.get("alg")
    key_id = header.get("kid")
    if algorithm not in settings.algorithms:
        raise OIDCAuthenticationError("The bearer token signing algorithm is not allowed.")
    if not isinstance(key_id, str) or not key_id or len(key_id) > 256:
        raise OIDCAuthenticationError("The bearer token signing key identifier is invalid.")
    if any(name in header for name in ("jku", "jwk", "x5u")):
        raise OIDCAuthenticationError("Untrusted token key references are not allowed.")

    try:
        signing_key = _jwks_client(settings).get_signing_key_from_jwt(candidate)
        claims = jwt.decode(
            candidate,
            signing_key.key,
            algorithms=list(settings.algorithms),
            audience=settings.audience,
            issuer=settings.issuer,
            leeway=settings.clock_skew_seconds,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except PyJWKClientConnectionError as exc:
        raise OIDCProviderUnavailableError(
            "The identity provider is temporarily unavailable."
        ) from exc
    except (PyJWKClientError, PyJWTError, OverflowError, TypeError) as exc:
        raise OIDCAuthenticationError("The bearer token could not be verified.") from exc

    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        not _finite_numeric_date(issued_at)
        or not _finite_numeric_date(expires_at)
        or expires_at <= issued_at
        or expires_at - issued_at > settings.max_token_age_seconds
        or time.time() - issued_at > settings.max_token_age_seconds + settings.clock_skew_seconds
    ):
        raise OIDCAuthenticationError("The bearer token lifetime is invalid.")

    audiences = claims.get("aud")
    if isinstance(audiences, list) and len(audiences) > 1:
        if claims.get("azp") != settings.audience:
            raise OIDCAuthenticationError("The bearer token authorized party is invalid.")
    elif "azp" in claims and claims.get("azp") != settings.audience:
        raise OIDCAuthenticationError("The bearer token authorized party is invalid.")

    subject = _validated_subject(claims)
    groups = _validated_groups(claims, settings.groups_claim)
    return OIDCIdentity(subject=subject, role=_role_for_groups(groups, settings))
