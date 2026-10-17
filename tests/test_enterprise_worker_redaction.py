from enterprise_worker_safety import safe_error


def test_redacts_exception_message():
    assert safe_error(RuntimeError("private")) == "Worker handler failed (RuntimeError)."
