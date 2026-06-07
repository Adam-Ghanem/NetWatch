from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from risk_engine import summarize_exposure, top_recommendations


@dataclass(frozen=True)
class AdvisorResult:
    title: str
    summary: str
    risk_level: str
    priorities: list[str]
    next_steps: list[str]
    confidence: str
    note: str


def _safe_count(rows: Iterable[dict]) -> int:
    return len(list(rows))


def _host_summary(host_rows: list[dict]) -> str:
    if not host_rows:
        return "No host discovery data is available yet. Run a Host Check or Network Scan first."
    return f"NetWatch has host data for {len(host_rows)} device(s) from the latest scan or inventory view."


def _port_summary(port_rows: list[dict]) -> tuple[str, str, list[str]]:
    if not port_rows:
        return (
            "No port audit data is available yet. Run a Port Audit on an authorized local host.",
            "Unknown",
            ["Run a Port Audit for one known internal IP address."],
        )

    exposure = summarize_exposure(port_rows)
    open_ports = [row for row in port_rows if row.get("Status") == "Open"]
    role_hint = "Unknown"
    if open_ports and "Device Role Hint" in open_ports[0]:
        role_hint = str(open_ports[0].get("Device Role Hint", "Unknown"))

    summary = (
        f"The latest port audit checked {exposure.checked} service(s). "
        f"It found {exposure.open_ports} open service(s), {exposure.high} high-risk item(s), "
        f"and an exposure score of {exposure.score}. Device role hint: {role_hint}."
    )

    priorities = []
    for row in top_recommendations(port_rows, limit=5):
        priorities.append(
            f"Review port {row.get('Port')} ({row.get('Service')}) — {row.get('Risk')} risk: {row.get('Recommendation')}"
        )

    if not priorities:
        priorities.append("No open service was detected in the configured common-port list.")

    return summary, exposure.level, priorities


def _inventory_summary(inventory_rows: list[dict]) -> str:
    if not inventory_rows:
        return "The local SQLite inventory is still empty. Results will appear after running checks."

    scored = [row for row in inventory_rows if int(row.get("exposure_score", 0)) > 0]
    return f"The local inventory contains {len(inventory_rows)} asset(s); {len(scored)} asset(s) have a non-zero exposure score."


def build_ai_advice(host_rows: Iterable[dict], port_rows: Iterable[dict], inventory_rows: Iterable[dict]) -> AdvisorResult:
    """Generate a local AI-style advisory summary from NetWatch results.

    This module does not call an external AI service. It uses deterministic logic so
    the project works offline and keeps scan data on the user's machine.
    """
    hosts = list(host_rows)
    ports = list(port_rows)
    inventory = list(inventory_rows)

    host_text = _host_summary(hosts)
    port_text, risk_level, priorities = _port_summary(ports)
    inventory_text = _inventory_summary(inventory)

    next_steps = [
        "Start with one known authorized host and compare Host Check with Port Audit results.",
        "Review high-risk services first, especially remote access, database, file-sharing and legacy services.",
        "Export an HTML report after each important scan and keep it with the project documentation.",
    ]

    if risk_level in {"High", "Medium"}:
        next_steps.insert(1, "Confirm whether each open service is expected and restricted by firewall rules.")
    elif risk_level == "Clean":
        next_steps.insert(1, "Repeat the check on another approved host to validate the network view.")

    summary = " ".join([host_text, port_text, inventory_text])
    confidence = "Medium" if ports else "Low"
    if hosts and ports and inventory:
        confidence = "High"

    return AdvisorResult(
        title="NetWatch AI Advisor",
        summary=summary,
        risk_level=risk_level,
        priorities=priorities,
        next_steps=next_steps,
        confidence=confidence,
        note="Local advisory engine only. It summarizes scan results and does not replace a full security audit.",
    )


def advice_to_markdown(result: AdvisorResult) -> str:
    priorities = "\n".join(f"- {item}" for item in result.priorities)
    next_steps = "\n".join(f"- {item}" for item in result.next_steps)
    return f"""# {result.title}

## Summary

{result.summary}

## Risk level

**{result.risk_level}**

## Priority findings

{priorities}

## Suggested next steps

{next_steps}

## Confidence

{result.confidence}

## Note

{result.note}
"""
