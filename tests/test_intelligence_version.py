from intelligence_version import intelligence_schema_version


def test_intelligence_schema_version_is_stable():
    assert intelligence_schema_version() == "1.1"
