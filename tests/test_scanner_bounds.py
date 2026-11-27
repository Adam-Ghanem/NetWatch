import math

import pytest

import network_scanner
import port_scanner
from port_scanner import scan_ports


def test_network_scanner_clamps_non_positive_worker_count(monkeypatch):
    monkeypatch.setattr(network_scanner, "ping_host", lambda ip: (True, "mock"))

    results = network_scanner.scan_network("192.168.1.0/30", max_workers=0)

    assert [row["IP Address"] for row in results] == ["192.168.1.1", "192.168.1.2"]


@pytest.mark.parametrize(
    "cidr",
    ["169.254.169.0/24", "169.254.170.0/24", "169.254.42.0/24"],
)
def test_network_scan_blocks_metadata_cidr_before_any_probe(monkeypatch, cidr):
    def unexpected_probe(ip):
        pytest.fail(f"Unexpected ping probe for {ip}")

    monkeypatch.setattr(network_scanner, "ping_host", unexpected_probe)

    with pytest.raises(ValueError, match="metadata"):
        network_scanner.scan_network(cidr)


@pytest.mark.parametrize(
    "target",
    ["fd20:ce::254", "169.254.170.2", "169.254.42.42", "fd00:42::42"],
)
def test_port_scan_blocks_metadata_endpoint_before_worker_submission(monkeypatch, target):
    def unexpected_scan(*args, **kwargs):
        pytest.fail("Metadata endpoint reached a port-scan worker")

    monkeypatch.setattr(port_scanner, "_scan_one_port", unexpected_scan)

    results = scan_ports(target)

    assert len(results) == 1
    assert results[0]["Status"] == "Blocked"
    assert "metadata" in results[0]["Recommendation"].lower()


@pytest.mark.parametrize("timeout", [0, -1, 10.1, math.inf, math.nan])
def test_port_scanner_rejects_unsafe_timeouts(timeout):
    with pytest.raises(ValueError, match="Timeout"):
        scan_ports("192.168.1.1", timeout=timeout)


def test_network_scan_requests_hostname_enrichment(monkeypatch):
    monkeypatch.setattr(network_scanner, "ping_host", lambda ip: (True, "mock"))
    calls = {}

    def enrich(rows, **kwargs):
        calls.update(kwargs)
        return rows

    monkeypatch.setattr(network_scanner, "enrich_host_rows", enrich)
    network_scanner.scan_network("192.168.1.0/30")

    assert calls["resolve_hostnames"] is network_scanner.HOSTNAME_LOOKUP_ENABLED
