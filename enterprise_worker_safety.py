"""Redact errors before recording queue failures."""

def safe_error(error: BaseException) -> str:
    return f"Worker handler failed ({error.__class__.__name__})."
