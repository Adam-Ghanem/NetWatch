"""Simple safe activity logging."""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path(os.getenv("NETWATCH_LOG_DIR", "logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOGGER = logging.getLogger("netwatch.activity")
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False
if not LOGGER.handlers:
    handler = RotatingFileHandler(
        LOG_DIR / "netwatch.log",
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    LOGGER.addHandler(handler)


def _clean_log_message(message: object, max_length: int = 2_000) -> str:
    text = str(message)
    cleaned = "".join(character if character.isprintable() else " " for character in text)
    return cleaned.strip()[:max_length]


def log_event(message: str) -> None:
    LOGGER.info("%s", _clean_log_message(message))
