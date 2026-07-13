from logger import sanitize_log_message


def test_log_message_removes_line_breaks_and_controls():
    cleaned = sanitize_log_message("scan ok\r\nFAKE ENTRY\x00")

    assert cleaned == "scan ok FAKE ENTRY"
