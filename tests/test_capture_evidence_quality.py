from capture_evidence_quality import assess_capture_evidence


def test_capture_evidence_quality_reports_unknown_without_statistics() -> None:
    result = assess_capture_evidence({"captured_packets": 12})

    assert result["status"] == "unknown"
    assert result["interfaces_reporting"] == 0
    assert result["payload_retained"] is False


def test_capture_evidence_quality_flags_reported_loss() -> None:
    result = assess_capture_evidence(
        {
            "interface_statistics": [
                {
                    "section": 1,
                    "interface_id": 0,
                    "received_packets": 100,
                    "dropped_packets": 4,
                    "os_dropped_packets": 0,
                }
            ]
        }
    )

    assert result["status"] == "loss_observed"
    assert result["latest_interface_statistics"] == [
        {
            "section": 1,
            "interface_id": 0,
            "received_packets": 100,
            "dropped_packets": 4,
            "os_dropped_packets": 0,
            "loss_reported": True,
        }
    ]


def test_capture_evidence_quality_uses_latest_statistics_per_interface() -> None:
    result = assess_capture_evidence(
        {
            "interface_statistics": [
                {
                    "section": 1,
                    "interface_id": 0,
                    "received_packets": 50,
                    "dropped_packets": 2,
                    "os_dropped_packets": 1,
                },
                {
                    "section": 1,
                    "interface_id": 0,
                    "received_packets": 90,
                    "dropped_packets": 0,
                    "os_dropped_packets": 0,
                },
            ]
        }
    )

    assert result["status"] == "no_loss_reported"
    assert result["interfaces_reporting"] == 1
    row = result["latest_interface_statistics"][0]
    assert row["received_packets"] == 90
    assert row["dropped_packets"] == 0


def test_capture_evidence_quality_does_not_claim_clean_capture_without_drop_counters() -> None:
    result = assess_capture_evidence(
        {
            "interface_statistics": [
                {
                    "section": 1,
                    "interface_id": 0,
                    "received_packets": 100,
                    "dropped_packets": None,
                    "os_dropped_packets": None,
                }
            ]
        }
    )

    assert result["status"] == "unknown"


def test_capture_evidence_quality_ignores_malformed_rows() -> None:
    result = assess_capture_evidence(
        {
            "interface_statistics": [
                "bad-row",
                {"section": -1, "interface_id": 0, "dropped_packets": 3},
                {"section": 1, "interface_id": True, "dropped_packets": 3},
            ]
        }
    )

    assert result["status"] == "unknown"
    assert result["interfaces_reporting"] == 0
