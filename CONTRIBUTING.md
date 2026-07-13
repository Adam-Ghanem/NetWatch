# Contributing to NetWatch

Thanks for helping improve NetWatch. Contributions should preserve its local-first, defensive-only security model.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
pre-commit install
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
```

## Before opening a pull request

Run:

```bash
black --check .
isort --check-only .
flake8 .
mypy .
pytest -q --cov=. --cov-report=term-missing
node --check frontend/app.js
docker compose config --quiet
```

Docker is required only for the Compose and container checks.

## Pull request expectations

- Keep changes focused and explain the operator value.
- Add or update tests for behavior changes.
- Do not add exploitation, brute force, credential testing, stealth, persistence, or evasion features.
- Keep scan targets restricted to explicitly authorized local networks.
- Avoid sending scan data to external services.
- Document configuration and security-impacting changes.
- Use clear, conventional commit-style messages when practical.

## Visual changes

For interface changes, include a screenshot or short recording using sample data. Never publish real customer, employer, school, or home-network identifiers.

## Reporting security issues

Do not open a public issue for a sensitive vulnerability. Follow the instructions in `SECURITY.md`.
