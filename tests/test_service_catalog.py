from service_catalog import guess_device_role, service_info


def test_service_info_known_port():
    info = service_info(22)
    assert info["protocol"] == "TCP"
    assert "SSH" in info["description"] or "Shell" in info["description"]


def test_service_info_unknown_port():
    info = service_info(9999)
    assert info["common_role"] == "Unknown"


def test_guess_device_role_database():
    assert guess_device_role([3306]) == "Database host"


def test_guess_device_role_web_admin():
    assert guess_device_role([443]) == "Web service or admin panel"


def test_guess_device_role_no_ports():
    assert guess_device_role([]) == "No open service detected in checked list"
