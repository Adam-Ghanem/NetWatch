"""Simple safe activity logging."""

from __future__ import annotations

import logging

from config import LOG_DIR

LOG_DIR.mkdir(parents=True, exist_ok=True)
LOGGER = logging.getLogger("netwatch.activity")
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False

if not LOGGER.handlers:
    handler = logging.FileHandler(LOG_DIR / "netwatch.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    LOGGER.addHandler(handler)


def sanitize_log_message(message: object, max_length: int = 1_000) -> str:
    text = str(message).replace("\r", " ").replace("\n", " ")
    text = "".join(character if character.isprintable() else " " for character in text)
    return " ".join(text.split())[:max_length]


def log_event(message: str) -> None:
    LOGGER.info(sanitize_log_message(message))
