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


def _event_view(changes_df: pd.DataFrame | None) -> pd.DataFrame:
    if changes_df is None or changes_df.empty:
        return pd.DataFrame()
    columns = [
        column
        for column in ("created_at", "ip_address", "event_label", "details")
        if column in changes_df.columns
    ]
    return changes_df[columns] if columns else pd.DataFrame()


def _audit_view(audit_df: pd.DataFrame | None) -> pd.DataFrame:
    if audit_df is None or audit_df.empty:
        return pd.DataFrame()
    columns = [
        column
        for column in ("created_at", "actor_role", "action", "target", "outcome", "details")
        if column in audit_df.columns
    ]
    return audit_df[columns] if columns else pd.DataFrame()


def _alert_view(alerts_df: pd.DataFrame | None) -> pd.DataFrame:
    if alerts_df is None or alerts_df.empty:
        return pd.DataFrame()
    columns = [
        column
        for column in (
            "last_seen_at",
            "severity",
            "title",
            "target",
            "occurrence_count",
            "status",
            "assigned_to",
            "due_at",
            "sla_state",
            "details",
            "resolution_note",
        )
        if column in alerts_df.columns
    ]
    return alerts_df[columns] if columns else pd.DataFrame()


def _policy_view(policies_df: pd.DataFrame | None) -> pd.DataFrame:
    if policies_df is None or policies_df.empty:
        return pd.DataFrame()
    columns = [
        column
        for column in (
            "name",
            "cidr",
            "interval_minutes",
            "enabled",
            "last_run_at",
            "next_run_at",
            "last_status",
        )
        if column in policies_df.columns
    ]
    return policies_df[columns] if columns else pd.DataFrame()


def _maintenance_view(maintenance_df: pd.DataFrame | None) -> pd.DataFrame:
    if maintenance_df is None or maintenance_df.empty:
        return pd.DataFrame()
    columns = [
        column
        for column in (
            "name",
            "policy_name",
            "starts_at",
            "ends_at",
            "reason",
            "enabled",
            "active",
            "created_by",
        )
        if column in maintenance_df.columns
    ]
    return maintenance_df[columns] if columns else pd.DataFrame()


def build_markdown_report(
    hosts_df: pd.DataFrame,
    ports_df: pd.DataFrame,
    changes_df: pd.DataFrame | None = None,
    audit_df: pd.DataFrame | None = None,
    alerts_df: pd.DataFrame | None = None,
    policies_df: pd.DataFrame | None = None,
    maintenance_df: pd.DataFrame | None = None,
) -> str:
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    exposure = (
        summarize_exposure(ports_df.to_dict("records"))
        if not ports_df.empty
        else summarize_exposure([])
    )

    events = _event_view(changes_df)
    audit_events = _audit_view(audit_df)
    alerts = _alert_view(alerts_df)
    policies = _policy_view(policies_df)
    maintenance = _maintenance_view(maintenance_df)
    open_alerts = (
        int((alerts["status"] == "open").sum()) if "status" in alerts.columns else len(alerts)
    )
    lines = [
        "# NetWatch Local Network Report",
        "",
        f"Generated at: `{created_at}`",
        "",
        "## Summary",
        "",
        f"- Saved assets: **{len(hosts_df) if not hosts_df.empty else 0}**",
        f"- Recent asset changes: **{len(events)}**",
        f"- Recent operational events: **{len(audit_events)}**",
        f"- Open operational alerts: **{open_alerts}**",
        f"- Approved scan policies: **{len(policies)}**",
        f"- Active maintenance windows: **{int(maintenance['active'].sum()) if 'active' in maintenance.columns else 0}**",
        f"- Ports checked: **{exposure.checked}**",
        f"- Open ports: **{exposure.open_ports}**",
        f"- High risk findings: **{exposure.high}**",
        f"- Medium risk findings: **{exposure.medium}**",
        f"- Exposure score: **{exposure.score}**",
        f"- Exposure level: **{exposure.level}**",
        "",
    ]

    if not hosts_df.empty:
        lines.extend(["## Asset inventory", "", _dataframe_to_markdown(hosts_df), ""])
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
    if not events.empty:
        lines.extend(["## Recent asset changes", "", _dataframe_to_markdown(events), ""])
    if not audit_events.empty:
        lines.extend(["## Operations audit log", "", _dataframe_to_markdown(audit_events), ""])
    if not alerts.empty:
        lines.extend(["## Operational alerts", "", _dataframe_to_markdown(alerts), ""])
    if not policies.empty:
        lines.extend(["## Approved scan policies", "", _dataframe_to_markdown(policies), ""])
    if not maintenance.empty:
        lines.extend(["## Maintenance windows", "", _dataframe_to_markdown(maintenance), ""])
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


def build_html_report(
    hosts_df: pd.DataFrame,
    ports_df: pd.DataFrame,
    changes_df: pd.DataFrame | None = None,
    audit_df: pd.DataFrame | None = None,
    alerts_df: pd.DataFrame | None = None,
    policies_df: pd.DataFrame | None = None,
    maintenance_df: pd.DataFrame | None = None,
) -> str:
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
    events = _event_view(changes_df)
    audit_events = _audit_view(audit_df)
    alerts = _alert_view(alerts_df)
    policies = _policy_view(policies_df)
    maintenance = _maintenance_view(maintenance_df)

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
<h2>Asset inventory</h2>{_html_table(hosts_df)}
<h2>Port assessment</h2>{_html_table(ports_df)}
<h2>Top recommendations</h2>{_html_table(recommendations)}
<h2>Recent asset changes</h2>{_html_table(events)}
<h2>Operations audit log</h2>{_html_table(audit_events)}
<h2>Operational alerts</h2>{_html_table(alerts)}
<h2>Approved scan policies</h2>{_html_table(policies)}
<h2>Maintenance windows</h2>{_html_table(maintenance)}
</main>
</body>
</html>"""


def build_pdf_report(
    hosts_df: pd.DataFrame,
    ports_df: pd.DataFrame,
    changes_df: pd.DataFrame | None = None,
    audit_df: pd.DataFrame | None = None,
    alerts_df: pd.DataFrame | None = None,
    policies_df: pd.DataFrame | None = None,
    maintenance_df: pd.DataFrame | None = None,
) -> bytes:
    """Render a bounded PDF hand-off report from the same redacted report inputs."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - exercised in minimal deployments
        raise RuntimeError("PDF report rendering is not installed.") from exc

    from io import BytesIO

    exposure = (
        summarize_exposure(ports_df.to_dict("records"))
        if not ports_df.empty
        else summarize_exposure([])
    )
    sections = (
        ("Asset inventory", hosts_df),
        ("Port assessment", ports_df),
        ("Recent asset changes", _event_view(changes_df)),
        ("Operations audit log", _audit_view(audit_df)),
        ("Operational alerts", _alert_view(alerts_df)),
        ("Approved scan policies", _policy_view(policies_df)),
        ("Maintenance windows", _maintenance_view(maintenance_df)),
    )
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="NetWatch Report",
        author="NetWatch",
    )
    styles = getSampleStyleSheet()
    styles["Title"].alignment = TA_CENTER
    story = [
        Paragraph("NetWatch Report", styles["Title"]),
        Paragraph(
            f"Generated {escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'))}. "
            "This report contains authorized local evidence and requires controlled handling.",
            styles["Normal"],
        ),
        Spacer(1, 8),
    ]
    summary_rows = [
        ["Assets", "Open ports", "High risk", "Exposure score", "Exposure level"],
        [
            str(len(hosts_df) if not hosts_df.empty else 0),
            str(exposure.open_ports),
            str(exposure.high),
            str(exposure.score),
            str(exposure.level),
        ],
    ]
    summary = Table(summary_rows, repeatRows=1)
    summary.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#e0f2fe")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#94a3b8")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.extend([summary, Spacer(1, 10)])

    for title, frame in sections:
        story.append(Paragraph(title, styles["Heading2"]))
        if frame is None or frame.empty:
            story.append(Paragraph("No data.", styles["Normal"]))
            story.append(Spacer(1, 5))
            continue
        limited = frame.head(100).fillna("")
        headers = [str(column)[:80] for column in limited.columns]
        rows = [headers]
        for _, row in limited.iterrows():
            rows.append([str(row[column])[:240] for column in limited.columns])
        table = Table(rows, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#cbd5e1")),
                    ("FONTSIZE", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f8fafc")],
                    ),
                ]
            )
        )
        story.extend([table, Spacer(1, 8)])
        if len(frame) > 100:
            story.append(
                Paragraph(
                    "Only the first 100 rows are included in this bounded export.", styles["Normal"]
                )
            )
            story.append(Spacer(1, 5))

    document.build(story)
    return buffer.getvalue()
