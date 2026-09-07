from __future__ import annotations

import hashlib
import socket
import ssl
from typing import Any

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
    negotiated protocol/cipher/ALPN metadata plus a SHA-256 certificate fingerprint,
    and never stores DER/PEM certificate contents.
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
    return evidence
