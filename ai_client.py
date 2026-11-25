"""Deprecated compatibility shim for the former raw-evidence OpenAI adapter.

The old helper serialized arbitrary asset and finding mappings directly to a
provider. It bypassed NetWatch Intelligence's de-identification, safety gates,
structured-output validation, and bounded transport. This shim preserves the
import and call signature but intentionally fails closed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence


class AIConfigurationError(RuntimeError):
    """Raised when a disabled or unsafe legacy AI integration is invoked."""


def analyze_with_ai(
    *,
    asset: Mapping[str, object],
    findings: Sequence[Mapping[str, object]] = (),
    model: str | None = None,
) -> str:
    """Reject legacy raw-evidence calls; use the supported Intelligence API.

    Arguments remain in the signature for source compatibility. They are
    deliberately neither inspected nor serialized, and no provider client is
    initialized.
    """
    del asset, findings, model
    raise AIConfigurationError(
        "The legacy raw-evidence AI adapter is disabled; use NetWatch "
        "Intelligence with a de-identified evidence snapshot."
    )
