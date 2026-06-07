import pandas as pd

from report_builder import build_markdown_report, summarize_ports


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
    assert summary["score"] == 7


def test_build_markdown_report_contains_summary():
    hosts = pd.DataFrame([{"IP Address": "192.168.1.10", "Status": "Online", "Details": "Host is online"}])
    ports = pd.DataFrame([{"Port": 22, "Service": "SSH", "Status": "Open", "Risk": "Medium", "Recommendation": "Use keys"}])

    report = build_markdown_report(hosts, ports)

    assert "NetWatch Local Network Report" in report
    assert "Online hosts found" in report
    assert "192.168.1.10" in report
    assert "SSH" in report
