"""Regression for notification configuration secret redaction."""

import logging

import notifications


def test_invalid_webhook_url_is_disabled_without_logging_secret(monkeypatch, caplog):
    secret = "private-webhook-token-should-never-appear"
    monkeypatch.setenv("NETWATCH_WEBHOOK_URL", f"https://hooks.example.test/path?token={secret}")
    monkeypatch.delenv("NETWATCH_SLACK_WEBHOOK_URL", raising=False)

    with caplog.at_level(logging.ERROR, logger=notifications.__name__):
        channels = notifications.notification_channels()

    assert len(channels) == 2
    assert channels[0].kind == "webhook"
    assert channels[0].enabled is False
    assert channels[0].url == ""
    assert channels[1].enabled is False
    assert secret not in caplog.text
    assert "hooks.example.test" not in caplog.text
    assert "notification_channel_disabled kind=webhook reason=unsafe_url" in caplog.text
