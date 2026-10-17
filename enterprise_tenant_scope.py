"""Validate explicit tenant scopes for enterprise queue workers."""

from __future__ import annotations

import re

_TENANT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,119}\Z")


def tenant_scope(value: str) -> str:
    if not isinstance(value, str) or not _TENANT.fullmatch(value):
        raise ValueError("A valid tenant scope is required.")
    return value
