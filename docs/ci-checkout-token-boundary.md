# Security CI checkout token boundary

The Security CI checkout uses `persist-credentials: false` so the job's GitHub token is not stored in the checked-out repository's Git configuration for subsequent dependency installation, build, and test commands. This is defense in depth for code executed from pull requests. The workflow retains read-only `contents` permissions and does not require authenticated Git pushes.

Regression: `python -m pytest -q tests/test_security_ci_checkout_credentials.py` checks the checkout contract. Review this setting when upgrading `actions/checkout` or changing workflow permissions.

Limitations: this setting does not prevent arbitrary network egress, protect secrets deliberately injected into other steps, or substitute for isolated runners, branch protection, and code review. It does not change application runtime behavior or enable scanning/remediation.
