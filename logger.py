"""Simple safe activity logging."""

from __future__ import annotations

import logging
from pathlib import Path

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOG_DIR / "netwatch.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)


def log_event(message: str) -> None:
    logging.info(message.replace("\n", " ").strip())
