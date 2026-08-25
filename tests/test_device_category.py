from device_category import classify_device


def test_mobile_category():
    assert (
        classify_device(hostname="Pixel-8", manufacturer="Google", platform="Android") == "mobile"
    )


def test_network_category():
    assert classify_device(device_type="Router", manufacturer="ZTE") == "network"


def test_server_category():
    assert classify_device(hostname="ubuntu-server", platform="Linux") == "server"


def test_unknown_category():
    assert classify_device(hostname="mystery-node") == "unknown"
