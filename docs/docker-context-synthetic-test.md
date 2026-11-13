# Synthetic Docker build-context regression

Run `pytest -q tests/test_docker_context_integration.py` with a local Docker daemon and BuildKit to exercise the real Docker ignore matcher. The test builds an ephemeral `FROM scratch` image with `--network none` and exports its filesystem; it never builds the production Dockerfile or uses real secrets.

The fixture expects root `.env.example` and a public file to survive, while root `.env`, `.env.local`, `.env.production`, and nested `.env*` files must not appear in the export. It skips when Docker is absent or its daemon is unavailable. A Docker installation without BuildKit local-export support fails rather than claiming validation.

This test verifies context exclusion, **not** secret scanning, historical Git layers, image provenance, runtime mounts, or production deployment. Keep PR #229's static contract tests as a daemon-independent baseline.
