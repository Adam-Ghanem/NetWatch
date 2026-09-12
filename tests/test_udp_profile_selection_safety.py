from __future__ import annotations

import pytest

import udp_service_scanner


def test_duplicate_udp_profiles_are_rejected_before_network_activity() -> None:
    called = False

    def factory(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("socket should not be created")

    with pytest.raises(ValueError, match="UDP service profiles must be unique"):
        udp_service_scanner.scan_udp_services(
            "192.168.1.10",
            services=("dns", "dns"),
            socket_factory=factory,
        )

    assert called is False
