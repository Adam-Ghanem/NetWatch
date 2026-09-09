from pathlib import Path


DASHBOARD = Path("frontend/tls-investigator.html")


def _source() -> str:
    return DASHBOARD.read_text(encoding="utf-8")


def test_tls_investigator_dashboard_uses_bounded_authenticated_read_api() -> None:
    source = _source()

    assert "/api/tls/investigator?" in source
    assert "'X-NetWatch-Key': key" in source
    assert "history_limit: '400'" in source
    assert 'max="1000" value="100"' in source
    assert "limit < 1 || limit > 1000" in source
    assert "cache: 'no-store'" in source


def test_tls_investigator_dashboard_exposes_safe_investigator_pivots() -> None:
    source = _source()

    for pivot in (
        "ip_address",
        "port",
        "protocol",
        "change_type",
        "severity",
        "alerts_only",
    ):
        assert pivot in source

    assert "change-facets" in source
    assert "severity-facets" in source
    assert "renderTimeline" in source
    assert "alert_recommended_count" in source


def test_tls_investigator_dashboard_keeps_dynamic_evidence_text_only() -> None:
    source = _source()

    assert ".innerHTML" not in source
    assert "textContent" in source
    assert "certificate bodies" in source
    assert "subject/issuer strings" in source
    assert "sessionStorage.getItem('netwatchApiKey')" in source
