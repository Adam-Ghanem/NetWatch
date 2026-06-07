from __future__ import annotations

from datetime import datetime
from typing import Iterable

import pandas as pd


def summarize_ports(port_rows: Iterable[dict]) -> dict[str, int]:
    rows = list(port_rows)
    open_rows = [row for row in rows if row.get("Status") == "Open"]
    high_rows = [row for row in open_rows if row.get("Risk") == "High"]
    medium_rows = [row for row in open_rows if row.get("Risk") == "Medium"]

    return {
        "checked": len(rows),
        "open": len(open_rows),
        "high": len(high_rows),
        "medium": len(medium_rows),
        "score": (len(high_rows) * 3) + (len(medium_rows) * 2) + len(open_rows),
    }


def build_markdown_report(hosts_df: pd.DataFrame, ports_df: pd.DataFrame) -> str:
    """Create a simple Markdown report from the latest in-memory scan results."""
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_count = len(hosts_df) if not hosts_df.empty else 0
    port_summary = summarize_ports(ports_df.to_dict("records")) if not ports_df.empty else {
        "checked": 0,
        "open": 0,
        "high": 0,
        "medium": 0,
        "score": 0,
    }

    lines = [
        "# NetWatch Local Network Report",
        "",
        f"Generated at: `{created_at}`",
        "",
        "## Summary",
        "",
        f"- Online hosts found: **{host_count}**",
        f"- Ports checked: **{port_summary['checked']}**",
        f"- Open ports: **{port_summary['open']}**",
        f"- High risk findings: **{port_summary['high']}**",
        f"- Medium risk findings: **{port_summary['medium']}**",
        f"- Exposure score: **{port_summary['score']}**",
        "",
    ]

    if not hosts_df.empty:
        lines.extend(["## Online hosts", "", hosts_df.to_markdown(index=False), ""])

    if not ports_df.empty:
        open_ports = ports_df[ports_df["Status"] == "Open"]
        lines.extend(["## Port assessment", "", ports_df.to_markdown(index=False), ""])
        if not open_ports.empty:
            lines.extend([
                "## Recommended checks",
                "",
                open_ports[["Port", "Service", "Risk", "Recommendation"]].to_markdown(index=False),
                "",
            ])

    lines.extend([
        "## Note",
        "",
        "This report is for authorized local network administration and learning only.",
    ])

    return "\n".join(lines)
