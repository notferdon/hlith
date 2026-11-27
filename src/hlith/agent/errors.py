# SPDX-License-Identifier: Apache-2.0
"""L1 boundary and execution errors."""

from __future__ import annotations

from ..contract.errors import EXIT_BOUNDARY


class RuntimeBoundary(RuntimeError):
    """Confinement or staging could not be established. Fail closed (exit 4)."""

    exit_status = EXIT_BOUNDARY


class EffectRejected(RuntimeBoundary):
    """The stage state cannot be turned into a trustworthy effect. Fail closed (exit 4)."""


class IndeterminateProposerCall(RuntimeError):
    """A command proposer may have side effects that cannot be inferred after its supervisor dies."""


__all__ = [
    "EffectRejected",
    "IndeterminateProposerCall",
    "RuntimeBoundary",
]
