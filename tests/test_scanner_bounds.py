import math

import pytest

import network_scanner
from port_scanner import scan_ports


def test_network_scanner_clamps_non_positive_worker_count(monkeypatch):
    monkeypatch.setattr(network_scanner, "ping_host", lambda ip: (True, "mock"))

    results = network_scanner.scan_network("192.168.1.0/30", max_workers=0)

    assert [row["IP Address"] for row in results] == ["192.168.1.1", "192.168.1.2"]


@pytest.mark.parametrize("timeout", [0, -1, 10.1, math.inf, math.nan])
def test_port_scanner_rejects_unsafe_timeouts(timeout):
    with pytest.raises(ValueError, match="Timeout"):
        scan_ports("192.168.1.1", timeout=timeout)
