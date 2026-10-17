"""Sanitize queue errors and calculate bounded retry times."""

from datetime import datetime, timedelta, timezone


def safe_error(error: BaseException) -> str:
    if str(error) == "No approved handler is registered for this job type.":
        return "No approved handler is registered for this job type."
    return f"Worker handler failed ({error.__class__.__name__})."


def retry_at(attempts: int) -> str:
    seconds = min(3600, 30 * (2 ** min(7, max(0, attempts - 1))))
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(
        timespec="seconds"
    )
