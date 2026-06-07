import pandas as pd

from export_utils import safe_csv_bytes


def test_safe_csv_bytes_prefixes_spreadsheet_formulas():
    df = pd.DataFrame({"value": ["=2+2", "+cmd", "normal"]})
    csv_text = safe_csv_bytes(df).decode("utf-8")

    assert "'=2+2" in csv_text
    assert "'+cmd" in csv_text
    assert "normal" in csv_text


def test_safe_csv_bytes_keeps_numbers():
    df = pd.DataFrame({"value": [10, 20]})
    csv_text = safe_csv_bytes(df).decode("utf-8")

    assert "10" in csv_text
    assert "20" in csv_text
