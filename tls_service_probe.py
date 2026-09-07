from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509

_TLS_PROBE_TIMEOUT_SECONDS = 0.5
_TLS_CERTIFICATE_MAX_BYTES = 64 * 1024
_TLS_VERSION_MAX_CHARS = 32
_TLS_CIPHER_MAX_CHARS = 96
_TLS_ALPN_MAX_CHARS = 32
_TLS_ALPN_PROTOCOLS = ("h2", "http/1.1")


def _default_tls_evidence() -> dict[str, str]:
    return {
        "Service Detection": "Port catalog",
        "Service Product": "",
        "Service Version": "",
        "Service Confidence": "Low",
    }


def _certificate_validity_evidence(
    certificate: bytes,
    *,
    now: datetime | None = None,
) -> dict[str, str]:
    """Return bounded certificate lifetime metadata without subject/issuer contents."""
    empty = {
        "TLS Certificate Not Before": "",
        "TLS Certificate Not After": "",
        "TLS Certificate Status": "Unknown",
        "TLS Certificate Days Remaining": "",
    }
    if not certificate:
        return empty
    try:
        parsed = x509.load_der_x509_certificate(certificate)
        not_before = parsed.not_valid_before_utc.astimezone(timezone.utc)
        not_after = parsed.not_valid_after_utc.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return empty

    observed_at = now or datetime.now(timezone.utc)
    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)
    observed_at = observed_at.astimezone(timezone.utc)

    if observed_at < not_before:
        status = "Not Yet Valid"
    elif observed_at > not_after:
        status = "Expired"
    else:
        status = "Valid"

    remaining_seconds = (not_after - observed_at).total_seconds()
    days_remaining = int(remaining_seconds // 86_400)
    if remaining_seconds > 0 and days_remaining == 0:
        days_remaining = 1

    return {
        "TLS Certificate Not Before": not_before.isoformat(timespec="seconds"),
        "TLS Certificate Not After": not_after.isoformat(timespec="seconds"),
        "TLS Certificate Status": status,
        "TLS Certificate Days Remaining": str(days_remaining),
    }


def probe_tls_service(
    sock: socket.socket,
    target: str,
    timeout: float,
    *,
    context_factory: Any = ssl.SSLContext,
) -> dict[str, str]:
    """Collect bounded TLS handshake metadata without retaining certificate bodies.

    The probe deliberately disables PKI verification because service discovery is not
    an authentication decision. The caller already established an authorized TCP
    connection; this function performs a single TLS client handshake, records only
    negotiated protocol/cipher/ALPN metadata, a SHA-256 certificate fingerprint, and
    certificate lifetime metadata. It never stores DER/PEM certificate contents or
    certificate subject/issuer strings.
    """
    try:
        context = context_factory(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(list(_TLS_ALPN_PROTOCOLS))
        sock.settimeout(min(timeout, _TLS_PROBE_TIMEOUT_SECONDS))
        with context.wrap_socket(sock, server_hostname=None) as tls_sock:
            version = (tls_sock.version() or "")[:_TLS_VERSION_MAX_CHARS]
            cipher_info = tls_sock.cipher()
            cipher = str(cipher_info[0])[:_TLS_CIPHER_MAX_CHARS] if cipher_info else ""
            alpn = (tls_sock.selected_alpn_protocol() or "")[:_TLS_ALPN_MAX_CHARS]
            certificate = tls_sock.getpeercert(binary_form=True) or b""
            if len(certificate) > _TLS_CERTIFICATE_MAX_BYTES:
                certificate = b""
    except (OSError, ssl.SSLError, socket.timeout, ValueError):
        return _default_tls_evidence()

    if not version:
        return _default_tls_evidence()

    fingerprint = hashlib.sha256(certificate).hexdigest() if certificate else ""
    evidence = {
        "Service Detection": "TLS handshake",
        "Service Product": "TLS",
        "Service Version": version,
        "Service Confidence": "High",
        "TLS Protocol": version,
        "TLS Cipher": cipher,
        "TLS ALPN": alpn,
        "TLS Certificate SHA256": fingerprint,
    }
    evidence.update(_certificate_validity_evidence(certificate))
    return evidence
