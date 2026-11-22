# Notification configuration redaction regression

The opt-in webhook configuration rejects URLs with query strings, fragments, or embedded credentials. A rejected channel must be disabled without preserving its URL in the public channel configuration or diagnostic logs.

`tests/test_notification_config_redaction.py` uses a synthetic query-string token, disables the alternate Slack channel, and asserts that the unsafe webhook is disabled and neither its hostname nor token appears in captured error logs. No HTTP request is made.

This is a narrow regression for configuration/logging behavior, not a proof against all secret disclosures, DNS rebinding, SSRF, or live delivery failures. Keep webhook destinations operator-approved and monitor changes through normal security review.
