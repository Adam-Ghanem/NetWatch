"""Guard the Docker context integration workflow against accidental silent skips."""

from pathlib import Path


def test_docker_context_ci_requires_real_docker_and_test_execution():
    workflow = Path(".github/workflows/docker-context-evidence.yml").read_text(
        encoding="utf-8"
    )
    assert "contents: read" in workflow
    assert '"ci/docker-context-evidence-*"' in workflow
    assert "docker info" in workflow
    assert "docker buildx version" in workflow
    assert "tests/test_docker_context_integration.py" in workflow
    assert "DOCKER_BUILDKIT" in workflow
    assert 'NETWATCH_REQUIRE_DOCKER_CONTEXT: "1"' in workflow
    integration = Path("tests/test_docker_context_integration.py").read_text(
        encoding="utf-8"
    )
    assert 'os.environ.get("NETWATCH_REQUIRE_DOCKER_CONTEXT") == "1"' in integration
    assert "pytest.fail(reason)" in integration
    assert "continue-on-error" not in workflow
    assert "|| true" not in workflow
