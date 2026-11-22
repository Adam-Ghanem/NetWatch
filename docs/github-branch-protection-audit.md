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
more branch path components. It evaluates active branch rulesets returned by GitHub. The helper supports
`~ALL` and resolves `~DEFAULT_BRANCH` using the repository's `default_branch`
metadata; if that metadata is unavailable, the audit is inconclusive. Unknown
special `~...` patterns remain inconclusive rather than being treated as matches.
A permission error is reported as inconclusive (exit code 2), never as an
unprotected branch. The ruleset reader intentionally fails closed if the first
100-entry page may be truncated.

## Required policy

- GitHub reports the branch as protected, or an active matching repository ruleset
  is present.
- At least one approving pull-request review, with stale approvals dismissed.
- Strict required status checks containing **Python CI** and **Security CI**.
- Required conversation/review-thread resolution.
- Enforcement for administrators, with no ruleset bypass actor used to satisfy
  the policy.
- Force pushes and branch deletion disabled.

Exit code 0 means all checks passed; 1 means the policy is noncompliant;
2 means the audit could not establish the policy. The JSON output lists each
check separately. This is an audit helper, not a branch-settings writer; apply
settings in GitHub repository settings and rerun the audit afterward.

## Review evidence — 2026-11-22

The repository branch listing reported main with protected: false, and the
repository rulesets endpoint returned an empty list. The connected integration
could not read the detailed classic-protection endpoint (HTTP 403), so required
review counts and status-check contexts were not independently inspectable in
that session. Run this helper with a token that has Administration: read
before treating the detailed policy as verified.

No network discovery, application traffic, production changes, or provider API
calls are involved.
