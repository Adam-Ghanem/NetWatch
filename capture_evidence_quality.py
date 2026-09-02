from __future__ import annotations

from collections.abc import Mapping

MAX_CAPTURE_INTERFACES = 1_000


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def assess_capture_evidence(import_result: Mapping[str, object]) -> dict[str, object]:
    """Summarize PCAPNG capture-loss evidence without inspecting packet payloads.

    Interface Statistics Block counters may be emitted repeatedly during a capture.
    To avoid double-counting cumulative counters, only the latest statistics record for
    each (section, interface_id) pair contributes to the aggregate summary.
    """

    raw_statistics = import_result.get("interface_statistics")
    if not isinstance(raw_statistics, list):
        raw_statistics = []

    latest: dict[tuple[int, int], Mapping[str, object]] = {}
    for item in raw_statistics[:MAX_CAPTURE_INTERFACES]:
        if not isinstance(item, Mapping):
            continue
        section = _non_negative_int(item.get("section"))
        interface_id = _non_negative_int(item.get("interface_id"))
        if section is None or interface_id is None:
            continue
        latest[(section, interface_id)] = item

    interfaces: list[dict[str, object]] = []
    reported_drop_sources = 0
    any_loss = False

    for (section, interface_id), item in sorted(latest.items()):
        received = _non_negative_int(item.get("received_packets"))
        interface_drops = _non_negative_int(item.get("dropped_packets"))
        os_drops = _non_negative_int(item.get("os_dropped_packets"))

        if interface_drops is not None:
            reported_drop_sources += 1
        if os_drops is not None:
            reported_drop_sources += 1
        if (interface_drops or 0) > 0 or (os_drops or 0) > 0:
            any_loss = True

        interfaces.append(
            {
                "section": section,
                "interface_id": interface_id,
                "received_packets": received,
                "dropped_packets": interface_drops,
                "os_dropped_packets": os_drops,
                "loss_reported": (interface_drops or 0) > 0 or (os_drops or 0) > 0,
            }
        )

    if not interfaces or reported_drop_sources == 0:
        status = "unknown"
        explanation = "Capture-loss counters were not available for the imported evidence."
    elif any_loss:
        status = "loss_observed"
        explanation = (
            "At least one capture interface reported packet loss; absence of a packet in the "
            "capture should not be treated as proof that it was absent on the network."
        )
    else:
        status = "no_loss_reported"
        explanation = (
            "Available interface statistics did not report capture drops. This is supporting "
            "evidence, not a guarantee that the capture is complete."
        )

    return {
        "status": status,
        "explanation": explanation,
        "interfaces_reporting": len(interfaces),
        "statistics_records_considered": min(len(raw_statistics), MAX_CAPTURE_INTERFACES),
        "latest_interface_statistics": interfaces,
        "payload_retained": False,
    }
