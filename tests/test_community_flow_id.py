import pytest

from community_flow_id import community_flow_id
from flow_analysis import summarize_flows


def test_matches_published_tcp_reference_vector():
    assert (
        community_flow_id("tcp", "10.0.0.1", "10.0.0.2", 10, 20)
        == "1:9j2Dzwrw7T9E+IZi4b4IVT66HBI="
    )


def test_reverse_direction_has_same_community_id():
    forward = community_flow_id("TCP", "10.0.0.1", "127.0.0.1", 1234, 80)
    reverse = community_flow_id("TCP", "127.0.0.1", "10.0.0.1", 80, 1234)

    assert forward == reverse
    assert forward.startswith("1:")


def test_udp_ipv6_is_supported_and_direction_independent():
    forward = community_flow_id("UDP", "2001:db8::1", "2001:db8::2", 5353, 53)
    reverse = community_flow_id("UDP", "2001:db8::2", "2001:db8::1", 53, 5353)

    assert forward == reverse
    assert forward.startswith("1:")


def test_unsupported_or_invalid_tuples_fail_closed():
    assert community_flow_id("ICMP", "10.0.0.1", "10.0.0.2", 0, 0) == ""
    assert community_flow_id("TCP", "not-an-ip", "10.0.0.2", 10, 20) == ""
    assert community_flow_id("TCP", "10.0.0.1", "2001:db8::2", 10, 20) == ""
    assert community_flow_id("TCP", "10.0.0.1", "10.0.0.2", -1, 20) == ""


def test_seed_is_bounded():
    with pytest.raises(ValueError, match="between 0 and 65535"):
        community_flow_id("TCP", "10.0.0.1", "10.0.0.2", 10, 20, seed=65_536)


def test_flow_summary_exposes_interoperable_community_id():
    flow = summarize_flows(
        [
            {
                "protocol": "TCP",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
                "source_port": 10,
                "destination_port": 20,
                "length_bytes": 60,
            }
        ]
    )[0]

    assert flow["community_id"] == "1:9j2Dzwrw7T9E+IZi4b4IVT66HBI="
