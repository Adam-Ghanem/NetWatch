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


def _host_summary(host_rows: list[dict]) -> str:
    if not host_rows:
        return "No host discovery data is available yet. Run a Host Check or Network Scan first."
    return (
        f"NetWatch has host data for {len(host_rows)} device(s) from the latest scan "
        "or inventory view."
    )


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
            f"Review port {row.get('Port')} ({row.get('Service')}) — "
            f"{row.get('Risk')} risk: {row.get('Recommendation')}"
        )

    if not priorities:
        priorities.append("No open service was detected in the configured common-port list.")

    return summary, exposure.level, priorities


def _inventory_summary(inventory_rows: list[dict]) -> str:
    if not inventory_rows:
        return (
            "The local SQLite inventory is still empty. Results will appear after running checks."
        )

    scored = [row for row in inventory_rows if _exposure_score(row) > 0]
    important = [
        row
        for row in inventory_rows
        if str(row.get("criticality", "")).title() in {"High", "Critical"}
    ]
    return (
        f"The local inventory contains {len(inventory_rows)} asset(s); "
        f"{len(scored)} asset(s) have a non-zero exposure score and "
        f"{len(important)} are marked High or Critical."
    )


def _exposure_score(row: dict) -> int:
    try:
        return int(row.get("exposure_score", 0))
    except (TypeError, ValueError):
        return 0


def _business_context_priorities(inventory_rows: list[dict]) -> tuple[list[str], list[str]]:
    priorities: list[str] = []
    next_steps: list[str] = []
    important = [
        row
        for row in inventory_rows
        if str(row.get("criticality", "")).title() in {"High", "Critical"}
    ]
    exposed = sorted(important, key=_exposure_score, reverse=True)
    exposed = [row for row in exposed if _exposure_score(row) > 0]
    for row in exposed[:3]:
        owner = str(row.get("owner") or "unassigned")
        department = str(row.get("department") or "department not set")
        priorities.append(
            f"Prioritize {row.get('ip_address')} ({row.get('criticality')}): exposure score "
            f"{_exposure_score(row)}, owner {owner}, {department}."
        )

    unowned = [row for row in important if not str(row.get("owner", "")).strip()]
    if unowned:
        addresses = ", ".join(str(row.get("ip_address")) for row in unowned[:5])
        next_steps.append(f"Assign accountable owners to important assets: {addresses}.")
    return priorities, next_steps


def _change_summary(change_rows: list[dict]) -> tuple[str, list[str], list[str]]:
    if not change_rows:
        return "No asset changes are recorded yet.", [], []

    new_assets = {
        str(row.get("ip_address"))
        for row in change_rows
        if row.get("event_type") == "new_asset" and row.get("ip_address")
    }
    returned_assets = {
        str(row.get("ip_address"))
        for row in change_rows
        if row.get("event_type") == "asset_returned" and row.get("ip_address")
    }
    not_observed_assets = {
        str(row.get("ip_address"))
        for row in change_rows
        if row.get("event_type") == "not_observed" and row.get("ip_address")
    }
    summary = (
        f"The recent change log contains {len(new_assets)} newly observed, "
        f"{len(returned_assets)} returned, and {len(not_observed_assets)} "
        "not-observed asset(s)."
    )
    priorities = []
    next_steps = []
    if not_observed_assets:
        priorities.append(
            "No reply was recorded for: "
            f"{', '.join(sorted(not_observed_assets))}. This is not definitive offline evidence."
        )
        next_steps.append(
            "Recheck not-observed assets with the system owner; ICMP filtering or a transient "
            "network condition can affect this signal."
        )
    if new_assets:
        priorities.append(
            "Review newly observed assets and confirm they are expected: "
            f"{', '.join(sorted(new_assets))}."
        )
    if returned_assets:
        next_steps.append(
            "Confirm why previously absent assets returned: "
            f"{', '.join(sorted(returned_assets))}."
        )
    return summary, priorities, next_steps


def build_advice(
    host_rows: Iterable[dict],
    port_rows: Iterable[dict],
    inventory_rows: Iterable[dict],
    change_rows: Iterable[dict] = (),
) -> AdvisorResult:
    """Build a local advisory summary from NetWatch results.

    This module uses deterministic project logic. It does not call any external
    service, so scan data stays on the user's machine.
    """
    hosts = list(host_rows)
    ports = list(port_rows)
    inventory = list(inventory_rows)
    changes = list(change_rows)

    host_text = _host_summary(hosts)
    port_text, risk_level, priorities = _port_summary(ports)
    inventory_text = _inventory_summary(inventory)
    change_text, change_priorities, change_steps = _change_summary(changes)
    business_priorities, business_steps = _business_context_priorities(inventory)
    priorities.extend(business_priorities)
    priorities.extend(change_priorities)

    next_steps = [
        "Start with one known authorized host and compare Host Check with Port Audit results.",
        (
            "Review high-risk services first, especially remote access, database, "
            "file-sharing and legacy services."
        ),
        (
            "Export an HTML report after each important scan and keep it with the "
            "project documentation."
        ),
    ]
    next_steps.extend(change_steps)
    next_steps.extend(business_steps)

    if risk_level in {"High", "Medium"}:
        next_steps.insert(
            1, "Confirm whether each open service is expected and restricted by firewall rules."
        )
    elif risk_level == "Clean":
        next_steps.insert(
            1, "Repeat the check on another approved host to validate the network view."
        )

    summary = " ".join([host_text, port_text, inventory_text, change_text])
    confidence = "Medium" if ports else "Low"
    if hosts and ports and inventory:
        confidence = "High"

    return AdvisorResult(
        title="NetWatch Risk Advisor",
        summary=summary,
        risk_level=risk_level,
        priorities=priorities,
        next_steps=next_steps,
        confidence=confidence,
        note=(
            "Local advisory engine only. It summarizes scan results and does not "
            "replace a full security audit."
        ),
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
