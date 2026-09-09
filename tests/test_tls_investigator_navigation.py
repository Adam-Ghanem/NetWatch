from pathlib import Path

DASHBOARD = Path("frontend/index.html")


def test_primary_navigation_links_to_tls_investigator() -> None:
    html = DASHBOARD.read_text(encoding="utf-8")

    assert 'href="/tls-investigator.html"' in html
    assert '<span class="nav-label">TLS investigator</span>' in html
