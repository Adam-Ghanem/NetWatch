from device_health import device_health


def test_device_health_full_inventory():
    result = device_health({"hostname": "host", "ip": "192.0.2.10", "services": {22: "ssh"}})
    assert result["score"] == 100
    assert result["status"] == "healthy"


def test_device_health_sparse_inventory():
    result = device_health({"ip": "192.0.2.10"})
    assert result["score"] == 33
    assert result["status"] == "incomplete"
