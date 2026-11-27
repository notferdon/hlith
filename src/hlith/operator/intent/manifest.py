# SPDX-License-Identifier: Apache-2.0
"""Host-side construction of declared intent from manifest claims."""

from __future__ import annotations


def intent_from_manifest(manifest: dict | None, approved_set_sha256: str | None):
    """Build L3 intent from manifest claims, preserving invalid raw deltas for fail-closed evaluation.

    The approved digest is only a human claim. L3 compares it with the canonical delta set and still judges the resulting
    confirmation obligation with the rest of the gate.
    """
    from ...agent import validate_deltas
    from ...obligation.intent import IntentDeclaration

    raw = (manifest or {}).get("deltas", [])
    try:
        deltas = tuple(validate_deltas(raw))
    except (ValueError, TypeError):
        deltas = tuple(raw) if isinstance(raw, list) else (raw,)
    return IntentDeclaration(deltas=deltas, approved_set_sha256=approved_set_sha256)


__all__ = ["intent_from_manifest"]
