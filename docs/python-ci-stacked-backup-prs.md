# Python CI for stacked backup pull requests

Python CI previously ran only for PRs targeting `main`. Backup hardening PRs are intentionally stacked: for example, #221 targets the head branch of #220. This meant the Python formatting, typing and pytest workflow did not run on those PRs, even when Security CI ran.

The pull-request target filter now also accepts `test/backup-*` and `feat/backup-*`. The existing push trigger remains restricted to `main`; no automatic merge, deployment, scans, or remediation is added. GitHub evaluates the **base branch** for `pull_request.branches`, not the source branch. A PR targeting an unrelated feature branch still needs a separate validation strategy.

Run `python -m pytest -q tests/test_python_ci_backup_triggers.py` to check the trigger contract. For an exact-head result, inspect GitHub Actions and confirm the workflow SHA, run conclusion, and PR head SHA; the PR test workflow normally checks out a synthetic merge ref, so do not confuse that with a standalone head-SHA run. The Codecov upload remains non-blocking and the workflow still requests its existing OIDC permission; this change does not expand that permission.
