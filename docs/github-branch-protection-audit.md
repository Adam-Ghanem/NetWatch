# Read-only GitHub branch-protection audit

NetWatch's Python and Security workflows are useful merge evidence only when the
repository requires them. This helper audits a selected GitHub branch without
changing repository settings, creating commits, or triggering workflows.

## Run locally

Use a fine-grained GitHub token with **Metadata: read** and **Administration:
read** for this repository. The token is read only and is read from the
GH_TOKEN or GITHUB_TOKEN environment variable; it is never accepted as a
command-line argument or included in output.

    export GH_TOKEN="$(gh auth token)"
    python scripts/audit_github_branch_protection.py --repo Adam-Ghanem/NetWatch --branch main
    unset GH_TOKEN

The audit checks classic branch protection and active repository rulesets that
match refs/heads/<branch>. Ref matching follows GitHub's `File::FNM_PATHNAME` behavior:
`*` and `?` do not cross `/`, while a complete `**` path component matches zero or
more branch path components. It evaluates active branch rulesets returned by GitHub.
The list endpoint returns ruleset summaries, so the helper fetches each ruleset's
detail before evaluating its target, conditions, and rules. It requests inherited
rulesets as well as repository-level rulesets. The helper supports `~ALL` and
resolves `~DEFAULT_BRANCH` using the repository's `default_branch` metadata; if
that metadata is unavailable, the audit is inconclusive. Unknown special
`~...` patterns remain inconclusive rather than being treated as matches.

GitHub may omit the `bypass_actors` field from ruleset details unless the caller
has write access to that ruleset. A missing field is **not** interpreted as an
empty bypass list: if a matching ruleset's bypass actors are hidden, the audit
returns **inconclusive** (exit code 2). This helper sends GET requests only and
never changes rulesets. Do not broaden token permissions solely to obtain a
green result; if bypass visibility is unavailable, retain the inconclusive
result and have an authorized administrator review the ruleset.

A permission error or incomplete ruleset response is reported as inconclusive
(exit code 2), never as an unprotected branch. The ruleset reader intentionally
fails closed if the first 100-entry page may be truncated.

## Required policy

- GitHub reports the branch as protected, or an active matching repository ruleset
  is present.
- At least one approving pull-request review, with stale approvals dismissed.
- Strict required status checks containing **Python CI** and **Security CI**, each bound to the GitHub Actions app (integration ID `15368`). Context-only or any-source checks are not accepted.
- Required conversation/review-thread resolution.
- Enforcement for administrators, with no ruleset bypass actor used to satisfy
  the policy.
- Force pushes and branch deletion disabled.

Exit code 0 means all checks passed; 1 means the policy is noncompliant;
2 means the audit could not establish the policy. The JSON output lists each
check separately. This is an audit helper, not a branch-settings writer; apply
settings in GitHub repository settings and rerun the audit afterward.

## Status-check identity — 2026-11-22

GitHub's check-runs API reported both existing workflow jobs with the generic name `test`, both from the GitHub Actions app (`15368`). Requiring only that shared context cannot distinguish the Python and Security workflows. Both workflows now assign distinct job display names (`Python CI` and `Security CI`). The audit also requires each classic `checks[].app_id` or ruleset `required_status_checks[].integration_id` to equal `15368`; a context with no source binding, or one bound to another app, does not satisfy the policy. The GitHub Actions app ID was verified from this repository's check-run metadata. GitHub documents that a required status check can be pinned to a specific GitHub App, while ruleset checks expose the optional `integration_id` source binding.

## Review evidence — 2026-11-22

The repository branch listing reported main with protected: false, and the
repository rulesets endpoint returned an empty list. The connected integration
could not read the detailed classic-protection endpoint (HTTP 403), so required
review counts and status-check contexts were not independently inspectable in
that session. Run this helper with a token that has Administration: read
before treating the detailed policy as verified.

No network discovery, application traffic, production changes, or provider API
calls are involved.
