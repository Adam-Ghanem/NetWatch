from os_fingerprint import fingerprint_os


def test_android_from_device_identity():
    result = fingerprint_os(hostname="Adam-Pixel-8", manufacturer="Google", device_family="Google Pixel")
    assert result.platform == "Android"
    assert result.confidence == "High"
    assert "Android/mobile identity evidence" in result.evidence


def test_ios_from_iphone_identity():
    result = fingerprint_os(hostname="iPhone", manufacturer="Apple", device_family="Apple iPhone")
    assert result.platform == "iOS/iPadOS"
    assert result.confidence == "High"


def test_linux_from_hostname_and_service():
    result = fingerprint_os(hostname="ubuntu-server", services={22: "OpenSSH"})
    assert result.platform == "Linux"
    assert result.confidence in {"Medium", "High"}


def test_windows_from_identity():
    result = fingerprint_os(hostname="WIN-PC", manufacturer="Microsoft", device_type="Windows computer")
    assert result.platform == "Windows"


def test_unknown_without_evidence():
    result = fingerprint_os()
    assert result.platform == "Unknown"
    assert result.confidence == "Low"
