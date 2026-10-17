"""Sanitize queue errors and calculate bounded retry times."""

from datetime import datetime, timedelta, timezone


def safe_error(error: BaseException) -> str:
    known = "No approved handler is registered for this job type."
    if type(error) is RuntimeError and error.args == (known,):
        return known
    return f"Worker handler failed ({type(error).__name__[:64]})."


def retry_at(attempts: int) -> str:
    seconds = min(3600, 30 * (2 ** min(7, max(0, attempts - 1))))
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(
        timespec="seconds"
    )
