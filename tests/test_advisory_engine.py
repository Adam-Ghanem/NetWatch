from advisory_engine import advice_to_markdown, build_advice


def test_advisor_low_confidence_without_data():
    result = build_advice([], [], [])

    assert result.risk_level == "Unknown"
    assert result.confidence == "Low"
    assert "Run a Port Audit" in result.priorities[0]


def test_advisor_prioritizes_high_risk_ports():
    ports = [
        {
            "Port": 22,
            "Service": "SSH",
            "Status": "Open",
            "Risk": "Medium",
            "Recommendation": "Use keys",
        },
        {
            "Port": 3389,
            "Service": "RDP",
            "Status": "Open",
            "Risk": "High",
            "Recommendation": "Restrict RDP",
        },
    ]
    hosts = [{"IP Address": "192.168.1.10", "Status": "Online"}]
    inventory = [{"ip_address": "192.168.1.10", "exposure_score": 6}]

    result = build_advice(hosts, ports, inventory)

    assert result.confidence == "High"
    assert result.risk_level in {"Medium", "High"}
    assert "3389" in result.priorities[0]


def test_advice_markdown_contains_sections():
    result = build_advice([], [], [])
    markdown = advice_to_markdown(result)

    assert "NetWatch Risk Advisor" in markdown
    assert "Priority findings" in markdown
    assert "Suggested next steps" in markdown
