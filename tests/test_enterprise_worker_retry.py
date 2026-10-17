from datetime import datetime, timezone

from enterprise_worker_safety import retry_at


def test_retry_backoff_is_bounded_and_increases():
    now = datetime.now(timezone.utc)
    first = (datetime.fromisoformat(retry_at(1)) - now).total_seconds()
    later = (datetime.fromisoformat(retry_at(4)) - now).total_seconds()
    capped = (datetime.fromisoformat(retry_at(100)) - now).total_seconds()
    assert 25 <= first <= 35
    assert 235 <= later <= 245
    assert 3595 <= capped <= 3605
