#!/usr/bin/env python3
"""Read-only audit of GitHub branch protection for a NetWatch repository."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

REQUIRED_CHECKS = {"Python CI", "Security CI"}
API_ROOT = "https://api.github.com"


def _validate_repo(value: str) -> str:
    parts = value.split("/")
    if len(parts) != 2 or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts):
        raise ValueError("Repository must use owner/name format.")
    return value


def _api_get(url: str, token: str | None, *, missing_ok: bool = False) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "NetWatch-branch-protection-audit",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if missing_ok and exc.code == 404:
            return None
        if exc.code == 403:
            raise PermissionError(
                "GitHub denied policy details; use a token with repository Administration: read."
            ) from None
        raise RuntimeError(f"GitHub API returned HTTP {exc.code}.") from None
    except (urllib.error.URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("Could not read a valid GitHub API response.") from None


def _matches_ref(pattern: str, ref: str) -> bool:
    return pattern == "~ALL" or fnmatch.fnmatchcase(ref, pattern)


def _matching_rulesets(rulesets: list[dict[str, Any]], branch: str) -> list[dict[str, Any]]:
    ref = f"refs/heads/{branch}"
    matched = []
    for ruleset in rulesets:
        if ruleset.get("target") != "branch" or ruleset.get("enforcement") != "active":
            continue
        ref_name = (ruleset.get("conditions") or {}).get("ref_name") or {}
        include = ref_name.get("include") or []
        exclude = ref_name.get("exclude") or []
        if any(_matches_ref(pattern, ref) for pattern in include) and not any(
            _matches_ref(pattern, ref) for pattern in exclude
        ):
            matched.append(ruleset)
    return matched


def _rules_of_type(rulesets: list[dict[str, Any]], rule_type: str) -> list[dict[str, Any]]:
    return [
        rule.get("parameters") or {}
        for ruleset in rulesets
        for rule in ruleset.get("rules", [])
        if rule.get("type") == rule_type
    ]


def _status_contexts(status: dict[str, Any]) -> set[str]:
    contexts = set(status.get("contexts") or [])
    contexts.update(
        check.get("context")
        for check in status.get("checks", [])
        if check.get("context")
    )
    return contexts


def evaluate_policy(
    branch_info: dict[str, Any],
    protection: dict[str, Any] | None,
    rulesets: list[dict[str, Any]],
    branch: str,
) -> dict[str, Any]:
    """Evaluate classic protection and active rulesets without changing GitHub."""
    matching = _matching_rulesets(rulesets, branch)
    classic = protection or {}

    review_policies = []
    classic_reviews = classic.get("required_pull_request_reviews")
    if isinstance(classic_reviews, dict):
        review_policies.append(classic_reviews)
    review_policies.extend(_rules_of_type(matching, "pull_request"))
    reviews_ok = any(
        int(policy.get("required_approving_review_count") or 0) >= 1
        and (
            policy.get("dismiss_stale_reviews") is True
            or policy.get("dismiss_stale_reviews_on_push") is True
        )
        for policy in review_policies
    )

    status_policies = []
    classic_status = classic.get("required_status_checks")
    if isinstance(classic_status, dict):
        status_policies.append(
            {
                "strict": classic_status.get("strict"),
                "contexts": _status_contexts(classic_status),
            }
        )
    status_policies.extend(
        {
            "strict": policy.get("strict_required_status_checks_policy"),
            "contexts": {
                check.get("context")
                for check in policy.get("required_status_checks", [])
                if check.get("context")
            },
        }
        for policy in _rules_of_type(matching, "required_status_checks")
    )
    strict_contexts = set().union(
        *(
            policy.get("contexts", set())
            for policy in status_policies
            if policy.get("strict") is True
        )
    )
    statuses_ok = REQUIRED_CHECKS.issubset(strict_contexts)

    conversation = classic.get("required_conversation_resolution") or {}
    conversation_ok = conversation.get("enabled") is True or any(
        policy.get("required_review_thread_resolution") is True
        for policy in _rules_of_type(matching, "pull_request")
    )

    force_pushes = classic.get("allow_force_pushes") or {}
    force_push_ok = force_pushes.get("enabled") is False or any(
        rule.get("type") == "non_fast_forward"
        for ruleset in matching
        for rule in ruleset.get("rules", [])
    )

    deletions = classic.get("allow_deletions") or {}
    deletion_ok = deletions.get("enabled") is False or any(
        rule.get("type") == "deletion"
        for ruleset in matching
        for rule in ruleset.get("rules", [])
    )

    admins = classic.get("enforce_admins") or {}
    no_ruleset_bypass = all(not ruleset.get("bypass_actors") for ruleset in matching)
    admin_ok = no_ruleset_bypass and (admins.get("enabled") is True or bool(matching))

    checks = {
        "branch_protection_or_matching_ruleset": (
            branch_info.get("protected") is True or bool(matching)
        ),
        "pull_request_review_and_stale_dismissal": reviews_ok,
        "strict_python_and_security_checks": statuses_ok,
        "conversation_resolution": conversation_ok,
        "admins_enforced_without_bypass": admin_ok,
        "force_push_disabled": force_push_ok,
        "branch_deletion_disabled": deletion_ok,
    }
    policy_present = protection is not None or bool(matching)
    ok = policy_present and all(checks.values())
    return {
        "ok": ok,
        "status": "compliant" if ok else "noncompliant",
        "repository_branch_protected_flag": branch_info.get("protected") is True,
        "classic_protection_present": protection is not None,
        "matching_active_rulesets": len(matching),
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="GitHub repository in owner/name format")
    parser.add_argument("--branch", default="main", help="Branch to audit (default: main)")
    args = parser.parse_args(argv)

    try:
        repo = _validate_repo(args.repo)
        branch_path = urllib.parse.quote(args.branch, safe="")
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        branch_info = _api_get(f"{API_ROOT}/repos/{repo}/branches/{branch_path}", token)
        protection = _api_get(
            f"{API_ROOT}/repos/{repo}/branches/{branch_path}/protection",
            token,
            missing_ok=True,
        )
        rulesets = _api_get(f"{API_ROOT}/repos/{repo}/rulesets?per_page=100", token)
        if not isinstance(rulesets, list) or len(rulesets) >= 100:
            raise RuntimeError(
                "Ruleset response is invalid or may be truncated; audit is inconclusive."
            )
        report = {
            "repository": repo,
            "branch": args.branch,
            **evaluate_policy(branch_info, protection, rulesets, args.branch),
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["ok"] else 1
    except PermissionError as exc:
        print(
            json.dumps(
                {
                    "ok": None,
                    "status": "inconclusive",
                    "repository": args.repo,
                    "branch": args.branch,
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2
    except (RuntimeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "ok": None,
                    "status": "inconclusive",
                    "repository": args.repo,
                    "branch": args.branch,
                    "error": str(exc),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
