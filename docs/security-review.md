# NetWatch v1 Security Review

## Scope

This review covers the default local deployment of NetWatch v1: one FastAPI process serving the responsive dashboard and protected API at `127.0.0.1:8000`.

## Threat model

NetWatch runs on a trusted operator machine connected to an authorized network. Relevant risks include:

- A malicious webpage attempting to call a locally running API
- An unauthorized local user accessing inventory or initiating scans
- Accidental scanning of public or oversized ranges
- Concurrent scans exhausting local resources
- Sensitive internal evidence leaking through files, reports, browser caching, or Git
- Container compromise receiving unnecessary privileges
- Dynamic scan values being interpreted as HTML or spreadsheet formulas

## Implemented controls

### API access

- All non-health endpoints require `X-NetWatch-Key`.
- The configured key is compared with `hmac.compare_digest`.
- Protected operations return HTTP 503 when no server key is configured.
- The dashboard stores the key only in session storage.

### Browser boundary

- Dashboard and API use the same origin by default.
- CORS permits only configured local origins.
- Content Security Policy restricts scripts, styles, connections, objects, frames, and forms.
- Frame embedding is denied.
- MIME sniffing is disabled.
- Referrer information is not sent.
- Camera, microphone, and geolocation permissions are disabled.
- API responses use `Cache-Control: no-store`.

### Scan safety

- Scan requests require explicit server-side authorization confirmation.
- Targets are restricted to approved local IPv4 ranges.
- Public and unsupported IPv6 targets are rejected.
- CIDR scans are limited to 256 hosts.
- API requests are rate limited per client and endpoint.
- Simultaneous scans are bounded.
- Port workers are bounded.
- The service list is intentionally conservative.

### Storage and output

- SQLite uses WAL mode and busy timeout.
- Timestamps are stored in UTC.
- Database and generated files are ignored by Git.
- CSV output reduces spreadsheet formula injection.
- HTML report values are escaped.
- The dashboard renders dynamic values with text nodes instead of HTML insertion.

### Container controls

- The container runs as a non-root user.
- Docker Compose drops all Linux capabilities and adds only `NET_RAW` for ping.
- `no-new-privileges` is enabled.
- Port `8000` is published only on `127.0.0.1`.
- Local data is persisted in named volumes.
- The image excludes local secrets and generated data through `.dockerignore`.

## Residual risks

- A user with access to the local machine and `.env` can obtain the API key.
- The API key is a single shared local secret, not user-level identity.
- Localhost binding does not protect against every malicious process running under the same user account.
- ICMP and TCP observations can be incomplete or misleading due to filtering and transient network conditions.
- The in-memory rate limiter resets when the process restarts and is not suitable for a multi-worker deployment.
- SQLite and the current schema are designed for one local operator, not high-concurrency multi-tenant use.
- Reports and screenshots can expose sensitive internal information if shared carelessly.

## Shared-deployment requirements

Do not expose the default service to other networks without adding:

- TLS
- SSO or organization authentication
- Role-based access control
- Managed secrets
- Network restrictions
- Centralized audit logging
- Monitoring and alerting
- Database backup and migration procedures
- Retention/deletion policy
- Dependency and container vulnerability management
- A deployment-specific penetration test and privacy review

## Review conclusion

The default NetWatch v1 configuration is appropriate for a trusted single-user local lab or internal demonstration when used only on authorized networks. It is not approved as-is for public, multi-user, or Internet-accessible deployment.
