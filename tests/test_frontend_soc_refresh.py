"""Frontend refresh guards: accessibility and asset integration stay dependency-free."""

from pathlib import Path

FRONTEND = Path("frontend")


def test_soc_refresh_assets_are_loaded_in_order() -> None:
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert html.index('/styles.css') < html.index('/soc-refresh.css')
    assert html.index('/app.js') < html.index('/ui-polish.js')
    assert 'href="#main-content"' in html
    assert 'id="main-content"' in html
    assert 'id="accent-switch"' in html


def test_soc_refresh_remains_local_and_preserves_keyboard_navigation() -> None:
    javascript = (FRONTEND / "ui-polish.js").read_text(encoding="utf-8")
    stylesheet = (FRONTEND / "soc-refresh.css").read_text(encoding="utf-8")
    assert "localStorage" in javascript
    assert "aria-current" in javascript
    assert "netwatchApiKey" not in javascript
    assert "fetch(" not in javascript
    assert ".skip-link:focus" in stylesheet
    assert "prefers-reduced-motion" in stylesheet
    for accent in ("cyan", "violet", "emerald"):
        assert accent in javascript
        assert accent in stylesheet
