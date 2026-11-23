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

OIDC upload remains enabled. The Python CI workflow therefore retains its
job-level `id-token: write` permission; do not broaden it to repository write
permissions. Coverage upload remains non-blocking (`fail_ci_if_error: false`)
and does not change test execution or coverage collection.
