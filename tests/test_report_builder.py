import pandas as pd

from report_builder import build_html_report, build_markdown_report, summarize_ports


def test_summarize_ports_counts_open_and_risk():
    rows = [
        {"Port": 22, "Status": "Open", "Risk": "Medium"},
        {"Port": 3389, "Status": "Open", "Risk": "High"},
        {"Port": 443, "Status": "Closed", "Risk": "None"},
    ]

    summary = summarize_ports(rows)

    assert summary["checked"] == 3
    assert summary["open"] == 2
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["score"] == 6


def test_build_markdown_report_contains_summary():
    hosts = pd.DataFrame(
        [{"IP Address": "192.168.1.10", "Status": "Online", "Details": "Host is online"}]
    )
    ports = pd.DataFrame(
        [
            {
                "Port": 22,
                "Service": "SSH",
                "Status": "Open",
                "Risk": "Medium",
                "Recommendation": "Use keys",
            }
        ]
    )

    report = build_markdown_report(hosts, ports)

    assert "NetWatch Local Network Report" in report
    assert "Exposure level" in report
    assert "192.168.1.10" in report
    assert "SSH" in report


def test_build_html_report_contains_sections():
    hosts = pd.DataFrame(
        [{"IP Address": "192.168.1.10", "Status": "Online", "Details": "Host is online"}]
    )
    ports = pd.DataFrame(
        [
            {
                "Port": 22,
                "Service": "SSH",
                "Status": "Open",
                "Risk": "Medium",
                "Recommendation": "Use keys",
            }
        ]
    )

    report = build_html_report(hosts, ports)

    assert "<html" in report
    assert "NetWatch Report" in report
    assert "Top recommendations" in report


def test_markdown_report_escapes_table_delimiters_and_line_breaks():
    hosts = pd.DataFrame([{"IP Address": "192.168.1.10", "Details": "router|gateway\nlocal"}])

    report = build_markdown_report(hosts, pd.DataFrame())

    assert "router\\|gateway local" in report
    assert "router|gateway\nlocal" not in report


def test_reports_include_recent_asset_changes_and_escape_html():
    changes = pd.DataFrame(
        [
            {
                "created_at": "2026-07-13T10:00:00+00:00",
                "ip_address": "192.168.1.20",
                "event_label": "New asset",
                "details": "router <approved>",
            }
        ]
    )

    markdown = build_markdown_report(pd.DataFrame(), pd.DataFrame(), changes)
    html = build_html_report(pd.DataFrame(), pd.DataFrame(), changes)

    assert "Recent asset changes: **1**" in markdown
    assert "192.168.1.20" in markdown
    assert "Recent asset changes" in html
    assert "router &lt;approved&gt;" in html
    assert "router <approved>" not in html


def test_reports_include_operations_audit_log_and_escape_values():
    audit = pd.DataFrame(
        [
            {
                "created_at": "2026-07-14T10:00:00+00:00",
                "actor_role": "operator",
                "action": "network_scan",
                "target": "192.168.1.0/24",
                "outcome": "completed",
                "details": "12 hosts <reviewed>",
            }
        ]
    )

    markdown = build_markdown_report(pd.DataFrame(), pd.DataFrame(), None, audit)
    html = build_html_report(pd.DataFrame(), pd.DataFrame(), None, audit)

    assert "Recent operational events: **1**" in markdown
    assert "Operations audit log" in markdown
    assert "network_scan" in markdown
    assert "Operations audit log" in html
    assert "12 hosts &lt;reviewed&gt;" in html
