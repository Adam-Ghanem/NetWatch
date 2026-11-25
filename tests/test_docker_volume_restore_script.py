from pathlib import Path

SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "smoke_docker_volume_restore.sh"
)


def test_docker_restore_smoke_is_network_isolated_and_provider_free() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert script.count("--network none") >= 3
    assert '--env "NETWATCH_AI_ENABLED=false"' in script
    assert '--env "NETWATCH_AI_AUTO_ANALYSIS_ENABLED=false"' in script
    assert '--env "NETWATCH_SCHEDULER_ENABLED=false"' in script
    assert '--env "NETWATCH_WEBHOOK_URL="' in script
    assert '--env "NETWATCH_SLACK_WEBHOOK_URL="' in script
    assert "OPENAI_API_KEY" not in script
    assert "ANTHROPIC_API_KEY" not in script


def test_docker_restore_smoke_checks_snapshot_and_restored_application() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "source.backup(destination)" in script
    assert "PRAGMA integrity_check" in script
    assert "PRAGMA foreign_key_check" in script
    assert 'docker volume rm "$SOURCE_VOLUME" "$SOURCE_LOG_VOLUME"' in script
    assert 'assert_application_evidence "$RESTORE_CONTAINER"' in script
    assert "verify_audit_integrity()" in script
