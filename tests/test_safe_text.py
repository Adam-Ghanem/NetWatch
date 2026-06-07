from safe_text import clean_text


def test_clean_text_escapes_html():
    assert clean_text("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_clean_text_trims_long_values():
    value = "a" * 400
    cleaned = clean_text(value, max_length=20)

    assert cleaned.endswith("...")
    assert len(cleaned) == 20
