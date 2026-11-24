import pytest

from udp_service_scanner import scan_udp_services


@pytest.mark.parametrize(
    "scope_id",
    ["0", "4294967296", "999999999999999999999999999999999999"],
)
def test_invalid_numeric_ipv6_scope_is_blocked_before_udp_socket_creation(scope_id):
    socket_created = False

    def fail_socket(*args, **kwargs):
        nonlocal socket_created
        socket_created = True
        raise AssertionError(
            "invalid IPv6 scope must be rejected before socket creation"
        )

    rows = scan_udp_services(
        f"fe80::10%{scope_id}",
        services=("dns",),
        socket_factory=fail_socket,
    )

    assert len(rows) == 1
    assert rows[0]["Status"] == "Blocked"
    assert rows[0]["Service Detection"] == "Target validation"
    assert socket_created is False
