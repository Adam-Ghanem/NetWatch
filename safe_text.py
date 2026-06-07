from __future__ import annotations

import html


def clean_text(value: object, max_length: int = 300) -> str:
    text = str(value)
    if len(text) > max_length:
        text = text[: max_length - 3] + "..."
    return html.escape(text, quote=True)
