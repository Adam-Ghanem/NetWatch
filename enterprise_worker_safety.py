"""Redact errors before recording queue failures."""


def safe_error(error: BaseException) -> str:
    if str(error) == "No approved handler is registered for this job type.":
        return "No approved handler is registered for this job type."
    return f"Worker handler failed ({error.__class__.__name__})."
