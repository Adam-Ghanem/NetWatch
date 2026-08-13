# Contributing to NetWatch

Thanks for helping improve NetWatch. The project is intentionally local-first and defensive: contributions should make authorized network visibility clearer, safer, easier to operate, or easier to understand.

> You do not need to be a network-security expert to contribute. Documentation, sanitized screenshots, reproducible tests, accessibility fixes, and small developer-experience improvements are valuable first contributions.

## The fastest path to a first contribution

1. Browse the [good first issue queue](https://github.com/Adam-Ghanem/NetWatch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) and the [help wanted queue](https://github.com/Adam-Ghanem/NetWatch/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22).
2. Comment on one issue to confirm that you are taking it, or open a focused issue if the gap is not listed.
3. Fork the repository, create a short-lived branch, make one focused change, and open a pull request against `main`.
4. Use sample data only. Never include real customer, employer, school, home-network, hostname, username, IP, credential, or provider-key data.

Good first contributions include improving a sentence in the README, adding a screenshot alt description, documenting a Windows or Docker edge case, adding a regression test for an already-defined behavior, or improving the clarity of an operator-facing message. A contribution should not add offensive scanning, brute force, credential testing, stealth, persistence, evasion, or public-target workflows.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
pre-commit install
```

On Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

The default application path is the FastAPI dashboard. Docker is required for the Compose and production-container checks, but not for documentation-only work or most unit tests.

## Before opening a pull request

Run the checks that match your change. The CI workflow runs the complete set.

```bash
black --check .
isort --check-only .
flake8 .
mypy .
pytest -q --cov=. --cov-report=term-missing
node --check frontend/app.js
docker compose config --quiet
```

For a documentation-only pull request, say so in the description and run at least `git diff --check`. For behavior changes, add or update tests and explain the operator-facing value.

## Pull request checklist

A useful pull request has a focused title, a short explanation of the problem, a concise summary of the change, and the checks that were run. If the change affects the UI, include a screenshot or short recording made with sanitized sample data. If it changes configuration or security boundaries, document the new assumption and the failure-safe behavior.

Please keep unrelated refactors out of the same pull request. Use clear conventional commit-style messages when practical, and prefer small reviewable changes over a large “cleanup” bundle.

## Safety and privacy boundaries

NetWatch is for networks and devices that you own or are explicitly authorized to assess. Keep scan targets restricted to approved private IPv4 ranges. Do not add exploitation, brute-force, credential-testing, stealth, persistence, or evasion capabilities. Do not send scan data to external services, and do not add a provider integration that bypasses the project’s de-identification and human-review boundaries.

Never commit `.env`, API keys, bearer tokens, private network identifiers, customer data, or recordings that expose a real environment. Security-sensitive issues should not be opened publicly; follow [`SECURITY.md`](SECURITY.md) instead.

## Visual changes

Capture interface changes at 1440 px or wider using a disposable test database and RFC1918 sample addresses. Show the authorization confirmation before a scan. Remove hostnames, usernames, employer names, school names, customer details, credentials, and other identifiers before committing an image or recording. Keep short demos under 20 seconds and prefer the repository’s existing sample-data previews as a visual reference.

## Questions and review

If an issue is unclear, ask a question before coding. Maintainers may request a smaller scope, additional tests, or clearer documentation of the security impact. A respectful, evidence-led review is more useful than a rushed merge.

## Reporting security issues

Do not open a public issue for a sensitive vulnerability. Follow the instructions in [`SECURITY.md`](SECURITY.md).
