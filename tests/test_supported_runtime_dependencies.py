"""Guard the primary NetWatch runtime from the vulnerable legacy UI dependency."""

from pathlib import Path


def test_patched_pillow_and_no_legacy_streamlit_in_production() -> None:
    dependencies = Path("requirements.txt").read_text(encoding="utf-8").splitlines()
    installed = [line.strip().lower() for line in dependencies if not line.startswith("#")]
    assert any(line.startswith("pillow==13.0.0") for line in installed)
    assert not any(line.startswith("streamlit") for line in installed)
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    compose = Path("docker-compose.yml").read_text(encoding="utf-8")
    makefile = Path("Makefile").read_text(encoding="utf-8")
    assert "EXPOSE 8000 8501" not in dockerfile
    assert "EXPOSE 8000" in dockerfile
    assert "  streamlit:" not in compose
    assert "Legacy Streamlit is unavailable" in makefile


def test_security_ci_checks_visual_preference_javascript() -> None:
    workflow = Path(".github/workflows/security-ci.yml").read_text(encoding="utf-8")
    assert "node --check frontend/app.js" in workflow
    assert "node --check frontend/ui-polish.js" in workflow
    assert "node --check frontend/theme-toggle.js" in workflow
