from __future__ import annotations

import pandas as pd

FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _clean_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    if value.startswith(FORMULA_PREFIXES):
        return "'" + value
    return value


def safe_csv_bytes(df: pd.DataFrame) -> bytes:
    """Export a DataFrame while reducing spreadsheet formula-injection risk."""
    if df.empty:
        return df.to_csv(index=False).encode("utf-8")
    cleaned = df.map(_clean_cell) if hasattr(df, "map") else df.applymap(_clean_cell)
    return cleaned.to_csv(index=False).encode("utf-8")
