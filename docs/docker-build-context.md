# Docker build-context environment-file boundary

The Dockerfiles copy the application build context into the image. Local
environment files may contain credentials, even when named `.env.local`,
`.env.production`, or placed inside a subdirectory. The `.dockerignore`
rules exclude root and nested `.env*` variants, while retaining the
documented, non-secret root `.env.example` for configuration guidance.

This is **defense in depth**, not a secret-management system. Keep secrets
outside the repository, use runtime secret injection, and avoid building from
directories containing other sensitive files. Docker ignore patterns do not
remove credentials already committed into source files or image layers.

Regression contract: `pytest -q tests/test_dockerignore_contract.py`.
For end-to-end confirmation on a machine with Docker, inspect the build
context and built image with synthetic marker files; never use real keys.
No deployment, image build, or credential access is required by this change.
