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

Python CI pins Codecov Action **v7.1.1** to the full commit SHA
[`303a32d7a59b442fa8d48b6a1cc6825c09c847a5`](https://github.com/codecov/codecov-action/commit/303a32d7a59b442fa8d48b6a1cc6825c09c847a5),
resolved from the signed upstream `v7.1.1` release commit. The exact workflow
reference is `codecov/codecov-action@303a32d7a59b442fa8d48b6a1cc6825c09c847a5 # v7.1.1`.
GitHub reports the upstream commit signature as verified; its release message is
`chore(release): 7.1.1 (#1973)`.

The pinned v7.1.1 composite action obtains its OIDC token through
`actions/github-script@ed597411d8f924073f98dfc5c65a23a2325f34cd # v8.0.0`,
also pinned to a full commit SHA and using the Node.js 24 action runtime. This
replaces the earlier Codecov v5 composite's `actions/github-script@v7`
(Node.js 20) helper without relying on a mutable nested action reference.

## Python CI OIDC boundary

The Python `test` job executes repository code and third-party dependencies. It
has `contents: read` and **does not** receive `id-token: write`. After tests
succeed, it uploads only the generated `coverage.xml` as the required
`python-coverage` Actions artifact. The artifact expires after one day, and a
missing report fails the test job.

A separate `coverage` job depends on the successful test job. It alone receives
`id-token: write`, checks out commit metadata, downloads the named artifact, and
runs the pinned Codecov v7.1.1 uploader with OIDC. The upload remains non-blocking
(`fail_ci_if_error: false`), preserving optional telemetry behavior. This keeps
OIDC token minting out of the test/dependency execution job; the dedicated
coverage job still trusts its pinned checkout, artifact actions, Codecov
uploader, and nested github-script action, so those components require normal
supply-chain review.

The artifact handoff uses the official immutable release commits:
- `actions/upload-artifact@v7`:
  [`cf430e030ddbb5b0abf93d22962f4752f3646cd9`](https://github.com/actions/upload-artifact/commit/cf430e030ddbb5b0abf93d22962f4752f3646cd9)
- `actions/download-artifact@v8`:
  [`9000827ccba6bdab643e8b6fd33ac0654aef8333`](https://github.com/actions/download-artifact/commit/9000827ccba6bdab643e8b6fd33ac0654aef8333)

Both releases use the Node.js 24 action runtime. The regression tests enforce
the full SHA references, required artifact handoff, and the absence of OIDC
permission from the Python test job. They also ensure this document describes
the same Codecov release and immutable reference as the executable workflow.


## Python CI pull-request coverage

The Python CI `pull_request` trigger intentionally has no `branches` allowlist.
GitHub evaluates a `pull_request.branches` filter against the PR's **base**
branch, not its source branch. A prefix allowlist can silently omit stacked PRs
when a new security, reliability, or maintenance branch prefix is introduced.
All pull requests targeting any base branch therefore receive formatting,
lint, type-check, compilation, and pytest validation. The `push` trigger remains
restricted to `main`.

The test job has only `contents: read` and never receives OIDC permission. The
separate Codecov coverage job runs for pushes and same-repository pull requests;
it is skipped for fork-originated pull requests. Fork PRs still run the full
Python test job, but do not receive an OIDC-backed coverage upload. This keeps
OIDC token minting outside untrusted fork workflows while preserving Python CI
coverage for stacked PR targets.
