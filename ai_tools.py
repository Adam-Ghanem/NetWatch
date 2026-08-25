from __future__ import annotations

from typing import Any


def asset_snapshot_tool(asset: dict[str, Any]) -> dict[str, Any]:
    """Return only the supplied, already-collected asset evidence."""
    return {k: asset[k] for k in ("id", "ip", "hostname", "fingerprint", "services") if k in asset}


def findings_tool(findings: list[dict[str, Any]], limit: int = 20) -> dict[str, Any]:
    """Return a bounded set of collected findings for agent context."""
    limit = max(1, min(20, int(limit)))
    return {"count": len(findings), "findings": findings[:limit]}


def register_default_tools(agent: Any, assets: dict[str, dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    from ai_agent import AgentTool

    agent.tools["asset_snapshot"] = AgentTool(
        "asset_snapshot", "Read already-collected asset evidence", lambda args: asset_snapshot_tool(assets[args["id"]])
    )
    agent.tools["findings"] = AgentTool(
        "findings", "Read bounded collected behavioral findings", lambda args: findings_tool(findings, args.get("limit", 20))
    )
