from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Iterable

DATA_DIR = Path("data")
HISTORY_FILE = DATA_DIR / "scan_history.csv"
FIELDNAMES = ["timestamp", "scan_type", "target", "summary", "status"]


def _ensure_file() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    if not HISTORY_FILE.exists():
        with HISTORY_FILE.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
            writer.writeheader()


def add_history(scan_type: str, target: str, summary: str, status: str = "completed") -> None:
    """Append one scan event to the local CSV history file."""
    _ensure_file()
    with HISTORY_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writerow(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_type": scan_type,
                "target": target,
                "summary": summary,
                "status": status,
            }
        )


def load_history(limit: int = 30) -> list[dict[str, str]]:
    """Load recent scan history. Missing history is treated as an empty list."""
    if not HISTORY_FILE.exists():
        return []

    with HISTORY_FILE.open("r", newline="", encoding="utf-8") as file:
        rows: Iterable[dict[str, str]] = csv.DictReader(file)
        history = list(rows)

    return list(reversed(history))[:limit]
