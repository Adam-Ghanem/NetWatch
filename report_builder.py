from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Iterable

import pandas as pd

from risk_engine import summarize_exposure, top_recommendations


def _markdown_cell(value: object) -> str:
    return (
        str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    )


def summarize_ports(port_rows: Iterable[dict]) -> dict[str, int]:
    summary = summarize_exposure(port_rows)
    return {
        "checked": summary.checked,
        "open": summary.open_ports,
        "high": summary.high,
        "medium": summary.medium,
        "score": summary.score,
    }


def _dataframe_to_markdown(df: pd.DataFrame) -> str:
    if df.empty:
        return "No data."

    columns = [_markdown_cell(column) for column in df.columns]
    header = "| " + " | ".join(columns) + " |"
    divider = "| " + " | ".join(["---"] * len(columns)) + " |"
    rows = []
    for _, row in df.iterrows():
        values = [_markdown_cell(row[column]) for column in df.columns]
        rows.append("| " + " | ".join(values) + " |")
    return "\n".join([header, divider, *rows])


def build_markdown_report(hosts_df: pd.DataFrame, ports_df: pd.DataFrame) -> str:
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    exposure = (
        summarize_exposure(ports_df.to_dict("records"))
        if not ports_df.empty
        else summarize_exposure([])
    )

    lines = [
        "# NetWatch Local Network Report",
        "",
        f"Generated at: `{created_at}`",
        "",
        "## Summary",
        "",
        f"- Online hosts found: **{len(hosts_df) if not hosts_df.empty else 0}**",
        f"- Ports checked: **{exposure.checked}**",
        f"- Open ports: **{exposure.open_ports}**",
        f"- High risk findings: **{exposure.high}**",
        f"- Medium risk findings: **{exposure.medium}**",
        f"- Exposure score: **{exposure.score}**",
        f"- Exposure level: **{exposure.level}**",
        "",
    ]

    if not hosts_df.empty:
        lines.extend(["## Online hosts", "", _dataframe_to_markdown(hosts_df), ""])
    if not ports_df.empty:
        open_ports = (
            ports_df[ports_df["Status"] == "Open"]
            if "Status" in ports_df.columns
            else pd.DataFrame()
        )
        lines.extend(["## Port assessment", "", _dataframe_to_markdown(ports_df), ""])
        if not open_ports.empty:
            recommendation_columns = [
                column
                for column in ("Port", "Service", "Risk", "Recommendation")
                if column in open_ports.columns
            ]
            if recommendation_columns:
                lines.extend(
                    [
                        "## Recommended checks",
                        "",
                        _dataframe_to_markdown(open_ports[recommendation_columns]),
                        "",
                    ]
                )
    lines.extend(["## Note", "", "Report generated from local NetWatch results."])
    return "\n".join(lines)


def _html_table(df: pd.DataFrame) -> str:
    if df.empty:
        return "<p>No data.</p>"
    headers = "".join(f"<th>{escape(str(column))}</th>" for column in df.columns)
    body_rows = []
    for _, row in df.iterrows():
        cells = "".join(f"<td>{escape(str(row[column]))}</td>" for column in df.columns)
        body_rows.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{headers}</tr></thead><tbody>{''.join(body_rows)}</tbody></table>"


def build_html_report(hosts_df: pd.DataFrame, ports_df: pd.DataFrame) -> str:
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    exposure = (
        summarize_exposure(ports_df.to_dict("records"))
        if not ports_df.empty
        else summarize_exposure([])
    )
    recommendations = (
        pd.DataFrame(top_recommendations(ports_df.to_dict("records")))
        if not ports_df.empty
        else pd.DataFrame()
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>NetWatch Report</title>
<style>
body {{ margin:0; font-family:Arial,sans-serif; background:#020617; color:#e5e7eb; }}
main {{ max-width:1050px; margin:auto; padding:32px 20px; }}
.hero,.card {{ border:1px solid #1f2937; border-radius:18px; background:#0f172a; padding:18px; }}
.cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin:20px 0; }}
.label {{ color:#94a3b8; font-size:12px; text-transform:uppercase; }}
.value {{ font-size:30px; font-weight:800; }}
table {{ width:100%; border-collapse:collapse; }}
th,td {{ border-bottom:1px solid #1f2937; padding:10px; text-align:left; }}
th {{ color:#7dd3fc; background:#111827; }}
</style>
</head>
<body>
<main>
<section class="hero"><h1>NetWatch Report</h1><p>Generated at {escape(created_at)}</p></section>
<section class="cards">
<div class="card"><div class="label">Open ports</div><div class="value">{exposure.open_ports}</div></div>
<div class="card"><div class="label">High risk</div><div class="value">{exposure.high}</div></div>
<div class="card"><div class="label">Score</div><div class="value">{exposure.score}</div></div>
<div class="card"><div class="label">Level</div><div class="value">{escape(exposure.level)}</div></div>
</section>
<h2>Online hosts</h2>{_html_table(hosts_df)}
<h2>Port assessment</h2>{_html_table(ports_df)}
<h2>Top recommendations</h2>{_html_table(recommendations)}
</main>
</body>
</html>"""
