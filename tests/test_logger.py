from logger import _clean_log_message


def test_log_messages_remove_control_characters_and_apply_a_length_limit():
    cleaned = _clean_log_message("scan complete\r\nFAKE EVENT\tignored\u2028next")
    limited = _clean_log_message("x" * 30, max_length=20)

    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert "\t" not in cleaned
    assert "\u2028" not in cleaned
    assert len(limited) == 20
