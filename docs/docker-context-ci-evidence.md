# Docker context CI evidence

The dedicated `Docker context evidence` workflow exercises the synthetic test introduced by PR #230 using Docker's real build-context matcher on an Ubuntu runner. It runs on pushes to `ci/docker-context-evidence-*` and on pull requests targeting `main` or `test/docker-context-synthetic-*`.

The job explicitly checks Docker daemon availability before invoking `python -m pytest -q -rs tests/test_docker_context_integration.py`. A missing Docker daemon therefore fails the job instead of silently skipping the integration check. The fixture uses `FROM scratch`, `--network none`, synthetic placeholder data, and a local filesystem export. It never builds or deploys the production image and never uses provider API credits.

For a passing result, inspect the exact head SHA and the job's **Exercise real Docker ignore matcher offline** step; generic Python/Security CI success alone does not prove this test executed. Pull-request runs may check out a generated merge commit. This validates only synthetic context exclusion, not historical image layers, runtime secrets, or production recovery. The companion contract test guards the workflow wiring without needing Docker.

Dependency order: PR #229 (ignore rules), PR #230 (integration test), then this PR. Keep drafts until review and actual CI evidence.
