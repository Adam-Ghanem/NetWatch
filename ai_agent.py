from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ai_client import OpenAIClient


@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    handler: Callable[[dict[str, Any]], dict[str, Any]]


class NetWatchAIAgent:
    """Tool-using defensive agent over already-collected NetWatch evidence."""

    def __init__(self, client: OpenAIClient, tools: list[AgentTool] | None = None):
        self.client = client
        self.tools = {tool.name: tool for tool in (tools or [])}

    def build_context(self, asset: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
        return {"asset": asset, "findings": findings, "available_tools": [
            {"name": t.name, "description": t.description} for t in self.tools.values()
        ]}

    def analyze(self, asset: dict[str, Any], findings: list[dict[str, Any]]) -> str:
        context = self.build_context(asset, findings)
        return self.client.analyze(context)

    def run_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name not in self.tools:
            raise KeyError(f"Unknown NetWatch AI tool: {name}")
        return self.tools[name].handler(arguments)
