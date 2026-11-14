# Dependency update review policy

Dependabot checks root Python requirements (including the development requirements
file) and GitHub Actions weekly on Monday. Minor and patch updates are grouped
by ecosystem, with at most five open Dependabot PRs per ecosystem. Major updates
remain separate for explicit review. This configuration does not merge PRs.

Review dependency release notes, advisories, lock/pin compatibility and any
new permissions before approving. Run Python CI and Security CI on the proposed
head; for Actions updates, inspect workflow permissions and action provenance.
A passing CI run does not prove that a dependency is free of vulnerabilities.
Do not use automated merges, deploy production, or supply paid provider keys
as part of update verification. Dependabot needs repository-side GitHub support
and permissions; this contract does not guarantee that GitHub will open PRs.
