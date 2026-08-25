from ai_agent import AgentTool, NetWatchAIAgent


class FakeClient:
    def analyze(self, context):
        return f"analysed:{context['asset'].get('id')}"


def test_agent_passes_collected_evidence_to_real_client_boundary():
    agent = NetWatchAIAgent(FakeClient())
    assert agent.analyze({"id": "asset-1"}, [{"kind": "new_port"}]) == "analysed:asset-1"


def test_agent_can_run_only_registered_tools():
    agent = NetWatchAIAgent(
        FakeClient(),
        [
            AgentTool(
                "asset_history",
                "Read local asset history",
                lambda args: {"asset": args["id"], "events": []},
            )
        ],
    )
    assert agent.run_tool("asset_history", {"id": "asset-1"}) == {"asset": "asset-1", "events": []}
