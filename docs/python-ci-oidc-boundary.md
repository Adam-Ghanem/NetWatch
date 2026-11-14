# Python CI OIDC boundary

The Python test job runs repository code and dependencies with read-only repository permissions and **without** GitHub OIDC token minting. It saves the generated `coverage.xml` as a named Actions artifact; missing coverage is a hard failure.

A separate `coverage` job runs only after the test job succeeds, downloads that artifact, and grants `id-token: write` solely for Codecov's OIDC authentication. Codecov upload retains `fail_ci_if_error: false`, preserving the existing optional telemetry behavior. No API credentials are required.

Run `python -m pytest -q tests/test_python_ci_oidc_boundary.py` for the static workflow regression. GitHub Actions is the authoritative integration check: verify both jobs on the PR head. This isolation reduces exposure of OIDC credentials to test code but does not make third-party actions or uploaded artifacts inherently trusted.
