# Python CI checkout credential boundary

The Python CI checkout now sets `persist-credentials: false` so the checkout action does not leave its GitHub token in local Git configuration for later dependency installation, tests, and coverage upload. The workflow still has read-only repository access and does not require authenticated Git pushes.

`tests/test_python_ci_checkout_token.py` guards this specific checkout setting against accidental removal. It is a static regression check, not a live token-exfiltration test.

This is a narrow defense: it does not prevent network egress, protect secrets explicitly injected into steps, or remove the existing workflow-level OIDC permission. PR #234 proposes a separate job-level OIDC isolation change and must be reconciled when reviewing workflow changes. PR #237 addresses the Security CI checkout independently.

Review Python CI and Security CI on the exact feature HEAD before merge. Do not merge automatically or interpret passing checks as a production security audit.
