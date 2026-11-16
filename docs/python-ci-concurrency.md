# Python CI concurrency

Python CI groups runs by workflow and pull request number (or Git ref for
non-PR events). When a new commit arrives on an open PR, its older Python CI
run is cancelled so the newest revision receives the runner budget.

Push runs on `main` are **not** cancelled by this policy. Different pull
requests use separate groups, so one contributor cannot cancel another PR's
Python CI. This does not alter test commands, workflow permissions, network
authorization, or production behavior.

The regression checks in `tests/test_python_ci_concurrency.py` guard the
group expression, PR-only cancellation, main and PR triggers, and existing
workflow permissions. GitHub Actions execution is the final verification
of the YAML expression; the tests do not emulate the Actions scheduler.
