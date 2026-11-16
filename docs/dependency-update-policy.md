# Dependency update review policy

Dependabot proposes weekly updates for root Python requirements (pip) and
GitHub Actions. Each ecosystem is limited to three open Dependabot PRs to
avoid overwhelming the existing review queue. Dependabot does not merge,
deploy, execute scans, or enable remediation.

Review every PR before merging: confirm the upstream changelog, compatibility,
security impact, pinned constraints and transitive dependency changes. Require
Python CI and Security CI on the proposed commit. For action updates, check
publisher provenance and the requested token permissions. Keep existing
authorization-first network scope and opt-in provider-cost boundaries.

Security advisories may require manual urgent review rather than waiting for
the weekly cadence. The config is proposal-only; GitHub must enable Dependabot
and permit PR creation for updates to appear. No updates are applied to main
without human review.
