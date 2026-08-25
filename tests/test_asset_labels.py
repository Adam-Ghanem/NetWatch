from asset_labels import asset_label


def test_platform_label():
    assert asset_label(platform="Android", device_category="mobile") == "Android mobile"


def test_unknown_label():
    assert asset_label(platform="", device_category="printer") == "Printer"
