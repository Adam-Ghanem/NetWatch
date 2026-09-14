from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

FLOW_SCHEMA_VERSION = "netwatch.flow.v1"
_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_SCHEMA_FILES = {
    "json": "netwatch-flow-v1.schema.json",
    "ndjson": "netwatch-flow-event-v1.schema.json",
}


def load_flow_schema(format_name: Literal["json", "ndjson"]) -> dict[str, object]:
    """Load the machine-readable schema for a supported NetWatch flow export format."""
    schema_path = _SCHEMA_DIR / _SCHEMA_FILES[format_name]
    with schema_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Invalid flow schema document: {schema_path.name}")
    return payload
