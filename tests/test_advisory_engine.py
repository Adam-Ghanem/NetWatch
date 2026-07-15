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


def test_advisor_surfaces_recent_asset_changes_without_overclaiming():
    changes = [
        {"ip_address": "192.168.1.20", "event_type": "new_asset"},
        {"ip_address": "192.168.1.21", "event_type": "not_observed"},
    ]

    result = build_advice([], [], [], changes)

    assert "1 newly observed" in result.summary
    assert any("192.168.1.20" in item for item in result.priorities)
    assert any("ICMP" in item for item in result.next_steps)


def test_advisor_prioritizes_important_business_assets_and_missing_owners():
    inventory = [
        {
            "ip_address": "192.168.1.70",
            "criticality": "Critical",
            "exposure_score": 9,
            "owner": "Platform Team",
            "department": "IT",
        },
        {
            "ip_address": "192.168.1.71",
            "criticality": "High",
            "exposure_score": 0,
            "owner": "",
            "department": "Operations",
        },
    ]

    result = build_advice([], [], inventory)

    assert "2 are marked High or Critical" in result.summary
    assert any("192.168.1.70" in item and "Platform Team" in item for item in result.priorities)
    assert any(
        "192.168.1.71" in item and "Assign accountable owners" in item for item in result.next_steps
    )
