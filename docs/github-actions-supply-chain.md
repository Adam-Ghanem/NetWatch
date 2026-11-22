# GitHub Actions supply-chain policy

NetWatch workflows pin every third-party action to a full 40-character commit SHA.
A trailing version comment (for example, `# v6`) is for reviewer readability only;
GitHub executes the immutable SHA, not the mutable release tag.

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
references that use mutable tags, branches, or abbreviated commit IDs. Local actions
(`./...`) and Docker actions (`docker://...`) are not treated as GitHub repository
action references by this check and require their own review.

Dependabot's GitHub Actions ecosystem can propose reviewed SHA updates when its
configuration is enabled; proposals still require human review and CI.
