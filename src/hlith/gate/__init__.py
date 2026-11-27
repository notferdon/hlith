# SPDX-License-Identifier: Apache-2.0
"""Layer 4 (gate/): sole writer of the target repository.

Re-exports legacy names from `_legacy` while callers migrate to `LocalGateService`.
"""

from __future__ import annotations

from .api import LocalGateService, landing_key_v2  # noqa: F401
from .git_write import apply_index_and_verify_tree, commit_staged, rollback_paths  # noqa: F401
from .journal import begin_journal, clear_journal, load_verified_journal  # noqa: F401

from ._legacy import (  # noqa: F401
    _HARDEN,
    _git,
    _run_git,
    _repository_attribute_violation,
    _submodule_exec_violation,
    _target_git_dir_violation,
    target_identity,
    executable_config,
    land,
    landing_key,
    recover,
)


from ..contract.legacy import GateDecision, GateOutcome, ObligationSet, ProposedEffect, decide  # noqa: E402,F401


def __getattr__(name: str):
    """Legacy compatibility: the old flat gate.py exposed every helper (head_tree, patch_violations, the journal
    helpers, ...). Resolve any name not exported explicitly from the preserved legacy module so callers and the kill-line
    suite keep working while they migrate to LocalGateService. Unknown names still raise AttributeError."""
    from . import _legacy
    try:
        return getattr(_legacy, name)
    except AttributeError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
