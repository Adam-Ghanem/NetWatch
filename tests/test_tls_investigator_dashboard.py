from pathlib import Path

DASHBOARD = Path("frontend/tls-investigator.html")
SCRIPT = Path("frontend/tls-investigator.js")


def _html() -> str:
    return DASHBOARD.read_text(encoding="utf-8")


def _javascript() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def test_tls_investigator_dashboard_uses_bounded_authenticated_read_api() -> None:
    html = _html()
    javascript = _javascript()

    assert "/api/tls/investigator?" in javascript
    assert "'X-NetWatch-Key': key" in javascript
    assert "history_limit: '400'" in javascript
    assert 'max="1000" value="100"' in html
    assert "limit < 1 || limit > 1000" in javascript
    assert "cache: 'no-store'" in javascript


def test_tls_investigator_dashboard_exposes_safe_investigator_pivots() -> None:
    source = _html() + _javascript()

    for pivot in ("ip_address", "port", "protocol", "change_type", "severity", "alerts_only"):
        assert pivot in source

    assert "change-facets" in source
    assert "severity-facets" in source
    assert "renderTimeline" in source
    assert "alert_recommended_count" in source


def test_tls_investigator_dashboard_is_csp_safe_and_uses_text_only_rendering() -> None:
    html = _html()
    javascript = _javascript()

    assert '<script src="/tls-investigator.js" defer></script>' in html
    assert '<link rel="stylesheet" href="/tls-investigator.css">' in html
    assert "<style" not in html
    assert "style=" not in html
    assert ".innerHTML" not in javascript
    assert "textContent" in javascript
    assert "certificate bodies" in html
    assert "subject/issuer strings" in html
    assert "sessionStorage.getItem('netwatchApiKey')" in javascript


def test_tls_investigator_dashboard_persists_shareable_scope_without_secrets() -> None:
    javascript = _javascript()

    assert "new URLSearchParams(window.location.search)" in javascript
    assert "window.history.replaceState" in javascript
    for parameter in (
        "ip_address",
        "port",
        "protocol",
        "change_type",
        "severity",
        "alerts_only",
        "limit",
    ):
        assert parameter in javascript

    sync_scope = javascript[
        javascript.index("function syncScopeToUrl") : javascript.index("function labelize")
    ]
    assert "netwatchApiKey" not in sync_scope
