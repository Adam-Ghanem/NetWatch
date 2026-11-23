# GitHub Actions supply-chain policy

NetWatch workflows pin every third-party action to a full 40-character commit SHA.
A trailing version comment (for example, `# v6`) is for reviewer readability only;
GitHub executes the immutable SHA, not the mutable release tag.

## Security CI Node.js runtime

Security CI pins `actions/setup-node` to the official `v6` tag target
[`249970729cb0ef3589644e2896645e5dc5ba9c38`](https://github.com/actions/setup-node/commit/249970729cb0ef3589644e2896645e5dc5ba9c38).
The action itself runs on the Node.js 24 action runtime; the separate
`node-version: "22"` input keeps Node.js 22 available to the workflow's
`node --check` commands.

This job only syntax-checks frontend JavaScript and does not install npm
dependencies. It sets `package-manager-cache: false` so setup-node cannot
implicitly enable package-manager caching for a future package manifest.

## Updating an action

1. Identify the intended upstream release and verify that its release tag resolves
   to the proposed full commit SHA in the action's official repository.
2. Review the upstream release notes and changes to the action implementation.
3. Update the SHA and the human-readable version comment together.
4. Run the workflow contract test and both Python CI and Security CI on the exact
   proposed commit before merging.
5. Keep workflow token permissions minimal; pinning does not make an overprivileged
   workflow safe.

The regression test `tests/test_workflow_action_pinning.py` rejects external action
references that use mutable tags, branches, or abbreviated commit IDs. It also
guards the reviewed setup-node v6 pin and the explicit cache opt-out. Local actions
(`./...`) and Docker actions (`docker://...`) are not treated as GitHub repository
action references by this check and require their own review.

Dependabot's GitHub Actions ecosystem can propose reviewed SHA updates when its
configuration is enabled; proposals still require human review and CI.

## Python CI coverage upload runtime

Python CI pins Codecov Action v6 to the full commit SHA
[`fb8b3582c8e4def4969c97caa2f19720cb33a72f`](https://github.com/codecov/codecov-action/commit/fb8b3582c8e4def4969c97caa2f19720cb33a72f),
resolved from the signed upstream `v6` release tag. This replaces v5, whose
composite action invoked `actions/github-script@v7` (Node.js 20). The reviewed
v6 composite action invokes the full-SHA-pinned `actions/github-script@v8`
(Node.js 24), removing that legacy nested runtime from the coverage-upload step.

## Python CI OIDC boundary

The Python `test` job executes repository code and third-party dependencies. It
has `contents: read` and **does not** receive `id-token: write`. After tests
succeed, it uploads only the generated `coverage.xml` as the required
`python-coverage` Actions artifact. The artifact expires after one day, and a
missing report fails the test job.

A separate `coverage` job depends on the successful test job. It alone receives
`id-token: write`, checks out commit metadata, downloads the named artifact, and
runs the pinned Codecov v6 uploader with OIDC. The upload remains non-blocking
(`fail_ci_if_error: false`), preserving optional telemetry behavior. This keeps
OIDC token minting out of the test/dependency execution job; the dedicated
coverage job still trusts its pinned checkout, artifact actions, and Codecov
uploader, so those components require normal supply-chain review.

The artifact handoff uses the official immutable release commits:
- `actions/upload-artifact@v7`:
  [`cf430e030ddbb5b0abf93d22962f4752f3646cd9`](https://github.com/actions/upload-artifact/commit/cf430e030ddbb5b0abf93d22962f4752f3646cd9)
- `actions/download-artifact@v8`:
  [`9000827ccba6bdab643e8b6fd33ac0654aef8333`](https://github.com/actions/download-artifact/commit/9000827ccba6bdab643e8b6fd33ac0654aef8333)

Both releases use the Node.js 24 action runtime. The regression tests enforce
the full SHA references, required artifact handoff, and the absence of OIDC
permission from the Python test job.
