from change_severity import change_severity


def test_identity_change_is_high():
    assert change_severity("identity_changed") == "high"


def test_new_exposure_is_high():
    assert change_severity("new_port", exposure_delta=1) == "high"


def test_non_exposure_change_is_low():
    assert change_severity("unknown") == "low"
