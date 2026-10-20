"""Guards for NetWatch's mint light theme and dark-mode fallback."""

from pathlib import Path

FRONTEND = Path("frontend")


def test_mint_styles_and_theme_toggle_are_loaded_after_soc_assets() -> None:
    html = (FRONTEND / "index.html").read_text(encoding="utf-8")
    assert 'data-theme="light"' in html
    assert html.index("/styles.css") < html.index("/soc-refresh.css")
    assert html.index("/soc-refresh.css") < html.index("/mint-light.css")
    assert html.index("/app.js") < html.index("/ui-polish.js")
    assert html.index("/ui-polish.js") < html.index("/theme-toggle.js")
    assert 'id="theme-switch"' in html
    assert 'aria-label="Switch to dark theme"' in html
    assert 'id="accent-switch"' in html


def test_mint_theme_preserves_data_and_protected_access() -> None:
    js = (FRONTEND / "theme-toggle.js").read_text(encoding="utf-8")
    css = (FRONTEND / "mint-light.css").read_text(encoding="utf-8")
    accent_js = (FRONTEND / "ui-polish.js").read_text(encoding="utf-8")
    assert "netwatch-ui-theme-v1" in js
    assert "aria-pressed" in js
    assert "localStorage" in js
    assert "fetch(" not in js
    assert "netwatchApiKey" not in js
    assert "data-theme=\"light\"" in css
    assert ".sidebar" in css
    assert ".nav-item.active" in css
    assert ".panel" in css
    assert ".table-wrap" in css
    assert "max-width: 460px" in css
    assert "prefers-reduced-motion" in css
    assert "return accents.includes(saved) ? saved : 'emerald'" in accent_js
