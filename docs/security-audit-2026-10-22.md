# Security and CI evidence snapshot — 2026-10-22

This is an evidence-based **repository audit snapshot**, not a completed penetration test, a certification, or a claim of enterprise production readiness.

## Verified GitHub workflow outcomes

| Ref / run | Result | Evidence |
| --- | --- | --- |
| `main` at `f128ee5cb695d23617798877e107be73331b3f3e` | Python CI **success** | [Run 39565500568](https://github.com/Adam-Ghanem/NetWatch/actions/runs/39565500568) |
| Same `main` SHA | Security CI **success** | [Run 39565500554](https://github.com/Adam-Ghanem/NetWatch/actions/runs/39565500554) |
| Screenshot-capture draft PR #191, initial SHA `1a045f2955d195af922b848ff6e6ce6c0aeda3ac` | Python CI **failure**, before tests; Black identified `scripts/capture_ui_screenshots.py` formatting | [Run 39698802966](https://github.com/Adam-Ghanem/NetWatch/actions/runs/39698802966) |
| Same initial PR SHA | Security CI **success** | [Run 39698802991](https://github.com/Adam-Ghanem/NetWatch/actions/runs/39698802991) |

The draft-PR formatting fix was submitted separately and must be validated by a new run before describing PR #191 as green. The results above describe their **specified SHAs**, not a promise that future commits pass.

## What the configured checks cover

- Python CI: dependency installation/check, Black and isort, Flake8, mypy, compilation, pytest coverage.
- Security CI: `pip-audit`, absence of tracked `.env`, secret-pattern gate, Bandit high-severity/high-confidence scan, JavaScript syntax, Compose validation, Docker build and non-root/NET_RAW boundary check, and pytest.
- Both workflows execute on GitHub Actions. A green check reports automated checks, **not** proof of absence of vulnerabilities.

## Added targeted regression coverage

`tests/test_security.py` exercises fail-closed handling of unsafe target literals, multicast/public/unspecified IPs, IPv4-mapped IPv6 literals, malformed scoped IPv6 addresses, non-approved CIDR ranges and excessive CIDR sizes. These tests should be run in a clean environment and pass in CI before merging.

## Outstanding gates before enterprise deployment

1. **High priority:** Independent scoped penetration test (RBAC/IDOR, CSRF/CORS/Host, SSRF, injection, malicious uploads, and secrets); record validated findings and retests.
2. **High priority:** TLS + OIDC production deployment with least-privilege roles and managed secrets; demonstrate end-to-end authorization tests.
3. **High priority:** Encrypted off-host backups, tested disaster recovery, append-only audit evidence export, documented retention.
4. **High priority:** Complete and test multi-tenant isolation and distributed workers before enabling `shared_service`; the existing adapter seams are fail-closed, not production clusters.
5. **Continuous:** Dependabot/dependency updates, container/image scan, frontend dependency review, reproducible benchmark and incident response drill.

See [production readiness assessment](production-readiness-report.md), [security review](security-review.md), [hardening guide](security-hardening.md), and [deployment](deployment.md).

## Reproduce locally

```bash
python -m pip install -r requirements-dev.txt
python -m pip check
black --check .
isort --check-only .
flake8 .
mypy .
pytest -q tests/test_security.py
pytest -q
pip-audit -r requirements-dev.txt
bandit -q -r . -x ./.venv,./venv,./tests -lll -iii
docker compose config --quiet
```

Use only synthetic data and approved laboratory networks for dynamic/security testing. This file contains no production secrets, private inventory, or test attack payloads.
