# Security CI concurrency policy

Security CI cancels an older in-progress run when a newer pull-request event for the same PR arrives. The concurrency group includes the workflow name and PR number, falling back to the Git ref for non-PR events. Different PRs therefore retain independent checks.

Cancellation is conditional on the event being a pull request: a push to `main` does **not** cancel another main push run. This keeps validation evidence for each main push. Python CI has a separate concurrency group and is unaffected.

The policy reduces redundant CI resource use; it does not change test coverage, authorization, secrets handling, or release gates. Source-level regression tests check the configuration. Actual cancellation timing depends on GitHub Actions scheduling and has not been validated by a live overlapping-run experiment.
