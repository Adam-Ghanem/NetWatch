from __future__ import annotations

import http.client
import json
import urllib.error

import pytest

from scripts import audit_github_branch_protection as audit


def _classic_protection():
    return {
        "required_pull_request_reviews": {
            "required_approving_review_count": 1,
            "dismiss_stale_reviews": True,
        },
        "required_status_checks": {
            "strict": True,
            "contexts": ["Python CI", "Security CI"],
        },
        "required_conversation_resolution": {"enabled": True},
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }


def _ruleset(*, bypass_actors=None, branch_pattern="refs/heads/main"):
    return {
        "name": "main-policy",
        "target": "branch",
        "enforcement": "active",
        "conditions": {
            "ref_name": {"include": [branch_pattern], "exclude": []},
        },
        "bypass_actors": bypass_actors or [],
        "rules": [
            {
                "type": "pull_request",
                "parameters": {
                    "required_approving_review_count": 1,
                    "dismiss_stale_reviews_on_push": True,
                    "required_review_thread_resolution": True,
                },
            },
            {
                "type": "required_status_checks",
                "parameters": {
                    "strict_required_status_checks_policy": True,
                    "required_status_checks": [
                        {"context": "Python CI"},
                        {"context": "Security CI"},
                    ],
                },
            },
            {"type": "non_fast_forward"},
            {"type": "deletion"},
        ],
    }


def test_compliant_classic_branch_protection_passes():
    result = audit.evaluate_policy({"protected": True}, _classic_protection(), [], "main")

    assert result["ok"] is True
    assert result["status"] == "compliant"
    assert all(result["checks"].values())


def test_branch_flag_must_report_protected():
    result = audit.evaluate_policy({"protected": False}, _classic_protection(), [], "main")

    assert result["ok"] is False
    assert result["checks"]["branch_protection_or_matching_ruleset"] is False


def test_missing_security_status_check_fails_closed():
    protection = _classic_protection()
    protection["required_status_checks"]["contexts"] = ["Python CI"]

    result = audit.evaluate_policy({"protected": True}, protection, [], "main")

    assert result["ok"] is False
    assert result["checks"]["strict_python_and_security_checks"] is False


def test_organization_level_protection_without_visible_details_is_inconclusive():
    result = audit.evaluate_policy({"protected": True}, None, [], "main")

    assert result["ok"] is None
    assert result["status"] == "inconclusive"


def test_no_protection_or_matching_ruleset_is_noncompliant():
    result = audit.evaluate_policy({"protected": False}, None, [], "main")

    assert result["ok"] is False
    assert result["status"] == "noncompliant"
    assert not any(result["checks"].values())


def test_compliant_active_ruleset_can_enforce_main_policy():
    result = audit.evaluate_policy({"protected": False}, None, [_ruleset()], "main")

    assert result["ok"] is True
    assert result["matching_active_rulesets"] == 1
    assert result["checks"]["branch_protection_or_matching_ruleset"] is True


def test_missing_ruleset_bypass_actor_visibility_is_inconclusive():
    ruleset = _ruleset()
    ruleset.pop("bypass_actors")

    result = audit.evaluate_policy({"protected": False}, None, [ruleset], "main")

    assert result["ok"] is None
    assert result["status"] == "inconclusive"
    assert "did not disclose bypass actors" in result["reason"]


def test_ruleset_bypass_actor_prevents_admin_enforcement():
    ruleset = _ruleset(bypass_actors=[{"actor_type": "RepositoryRole", "bypass_mode": "always"}])

    result = audit.evaluate_policy({"protected": True}, None, [ruleset], "main")

    assert result["ok"] is False
    assert result["checks"]["admins_enforced_without_bypass"] is False


def test_ruleset_for_another_branch_does_not_protect_main():
    result = audit.evaluate_policy(
        {"protected": False},
        None,
        [_ruleset(branch_pattern="refs/heads/release/*")],
        "main",
    )

    assert result["ok"] is False
    assert result["matching_active_rulesets"] == 0


def test_single_star_does_not_match_nested_branch_path_components():
    result = audit.evaluate_policy(
        {"protected": False},
        None,
        [_ruleset(branch_pattern="refs/heads/release/*")],
        "release/v1/hotfix",
    )

    assert result["matching_active_rulesets"] == 0
    assert result["ok"] is False


@pytest.mark.parametrize("branch", ["release/stable", "release/v1/hotfix/stable"])
def test_double_star_matches_zero_or_more_branch_path_components(branch):
    result = audit.evaluate_policy(
        {"protected": False},
        None,
        [_ruleset(branch_pattern="refs/heads/release/**/stable")],
        branch,
    )

    assert result["matching_active_rulesets"] == 1
    assert result["checks"]["branch_protection_or_matching_ruleset"] is True


def test_default_branch_pattern_matches_only_the_repository_default_branch():
    ruleset = _ruleset(branch_pattern="~DEFAULT_BRANCH")

    default_result = audit.evaluate_policy(
        {"protected": False}, None, [ruleset], "main", default_branch="main"
    )
    other_result = audit.evaluate_policy(
        {"protected": False}, None, [ruleset], "release/v1", default_branch="main"
    )

    assert default_result["matching_active_rulesets"] == 1
    assert default_result["ok"] is True
    assert other_result["matching_active_rulesets"] == 0
    assert other_result["ok"] is False


def test_default_branch_pattern_requires_repository_metadata():
    with pytest.raises(ValueError, match="default branch is unavailable"):
        audit.evaluate_policy(
            {"protected": False},
            None,
            [_ruleset(branch_pattern="~DEFAULT_BRANCH")],
            "main",
        )


def test_default_branch_exclusion_overrides_all_branches_include():
    ruleset = _ruleset(branch_pattern="~ALL")
    ruleset["conditions"]["ref_name"]["exclude"] = ["~DEFAULT_BRANCH"]

    result = audit.evaluate_policy(
        {"protected": False}, None, [ruleset], "main", default_branch="main"
    )

    assert result["matching_active_rulesets"] == 0
    assert result["ok"] is False


def test_unknown_special_ruleset_ref_pattern_is_inconclusive():
    with pytest.raises(ValueError, match="Unsupported GitHub ruleset ref pattern"):
        audit.evaluate_policy(
            {"protected": False},
            None,
            [_ruleset(branch_pattern="~UNSUPPORTED")],
            "main",
            default_branch="main",
        )


def test_cli_resolves_repository_default_branch_before_ruleset_evaluation(monkeypatch, capsys):
    calls = []

    def fake_api_get(url, token, *, missing_ok=False):
        calls.append(url)
        if url.endswith("/repos/owner/repo"):
            return {"default_branch": "main"}
        if url.endswith("/branches/main"):
            return {"protected": False}
        if url.endswith("/branches/main/protection"):
            return None
        if url.endswith("/rulesets?per_page=100"):
            return [{"id": 42}]
        if url.endswith("/rulesets/42?includes_parents=true"):
            return _ruleset(branch_pattern="~DEFAULT_BRANCH")
        raise AssertionError(f"Unexpected API URL: {url}")

    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(audit, "_api_get", fake_api_get)

    assert audit.main(["--repo", "owner/repo", "--branch", "main"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["status"] == "compliant"
    assert calls[0] == "https://api.github.com/repos/owner/repo"
    assert "https://api.github.com/repos/owner/repo/rulesets/42?includes_parents=true" in calls


def test_cli_does_not_assume_hidden_ruleset_bypass_actors_are_empty(monkeypatch, capsys):
    def fake_api_get(url, token, *, missing_ok=False):
        if url.endswith("/repos/owner/repo"):
            return {"default_branch": "main"}
        if url.endswith("/branches/main"):
            return {"protected": False}
        if url.endswith("/branches/main/protection"):
            return None
        if url.endswith("/rulesets?per_page=100"):
            return [{"id": 42}]
        if url.endswith("/rulesets/42?includes_parents=true"):
            detail = _ruleset(branch_pattern="~DEFAULT_BRANCH")
            detail.pop("bypass_actors")
            return detail
        raise AssertionError(f"Unexpected API URL: {url}")

    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(audit, "_api_get", fake_api_get)

    assert audit.main(["--repo", "owner/repo", "--branch", "main"]) == 2
    report = json.loads(capsys.readouterr().out)

    assert report["ok"] is None
    assert report["status"] == "inconclusive"
    assert "bypass actors" in report["reason"]


def test_permission_denial_is_inconclusive_and_does_not_echo_response_body(monkeypatch):
    def forbidden(_request, timeout):
        raise urllib.error.HTTPError(
            "https://api.github.com/private",
            403,
            "Forbidden",
            hdrs=http.client.HTTPMessage(),
            fp=None,
        )

    monkeypatch.setattr(audit.urllib.request, "urlopen", forbidden)

    with pytest.raises(PermissionError, match="Administration: read") as error:
        audit._api_get("https://api.github.com/private", "synthetic-token")

    assert "synthetic-token" not in str(error.value)


def test_repository_validation_rejects_url_and_extra_path():
    with pytest.raises(ValueError, match="owner/name"):
        audit._validate_repo("https://github.com/owner/repo")
    with pytest.raises(ValueError, match="owner/name"):
        audit._validate_repo("owner/repo/extra")
