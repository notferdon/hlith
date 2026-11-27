# SPDX-License-Identifier: Apache-2.0
"""Compatibility shim for hlith.runtime (moved to hlith.agent.capture + hlith.agent.supervisor)."""

from .agent.capture import (
    DELTA_KINDS,
    DELTA_TYPED_CLASSES,
    MANIFEST_NAME,
    MAX_DELTAS,
    MAX_EFFECT_BYTES,
    MAX_EFFECT_ENTRIES,
    MAX_LITERAL_INPUTS,
    MAX_MANIFEST_BYTES,
    MAX_MANIFEST_PATHS,
    MAX_REL_PATH_BYTES,
    MAX_STAGE_DEPTH,
    DeclaredEffects,
    DeltaEffect,
    EffectRejected,
    ObservedChange,
    Reconciliation,
    RuntimeBoundary,
    StageScan,
    WorkerRun,
    _attr_pattern,
    _check_json_value,
    _KIND_VOCAB,
    _diff_stage,
    _git,
    _materialise,
    _observed,
    _reject_special_files,
    _risk_flags,
    _scan_stage,
    canonical_delta_set,
    delta_set_sha256,
    is_advisory,
    read_manifest,
    read_manifest_full,
    reconcile,
    validate_delta,
    validate_deltas,
    worktree_digest,
)
from .agent.supervisor import resume_agent_worker, run_worker

__all__ = [
    "DELTA_KINDS",
    "DELTA_TYPED_CLASSES",
    "MANIFEST_NAME",
    "MAX_DELTAS",
    "MAX_EFFECT_BYTES",
    "MAX_EFFECT_ENTRIES",
    "MAX_LITERAL_INPUTS",
    "MAX_MANIFEST_BYTES",
    "MAX_MANIFEST_PATHS",
    "MAX_REL_PATH_BYTES",
    "MAX_STAGE_DEPTH",
    "DeclaredEffects",
    "DeltaEffect",
    "EffectRejected",
    "ObservedChange",
    "Reconciliation",
    "RuntimeBoundary",
    "StageScan",
    "WorkerRun",
    "_attr_pattern",
    "_diff_stage",
    "_git",
    "_materialise",
    "_observed",
    "_reject_special_files",
    "_risk_flags",
    "_scan_stage",
    "canonical_delta_set",
    "delta_set_sha256",
    "is_advisory",
    "read_manifest",
    "read_manifest_full",
    "reconcile",
    "resume_agent_worker",
    "run_worker",
    "validate_delta",
    "validate_deltas",
    "worktree_digest",
]


def __getattr__(name: str):
    """Legacy compatibility: the old flat runtime.py exposed ProposedEffect, EXIT_BOUNDARY, GrantError, Profile, run_confined
    and many private helpers. Resolve any name not re-exported above from the modules it moved to, so the kill-line suite
    and older callers keep working while they migrate. Unknown names still raise AttributeError."""
    import importlib

    for mod in ("hlith.agent.capture", "hlith.agent.supervisor", "hlith.contract.legacy"):
        m = importlib.import_module(mod)
        if hasattr(m, name):
            return getattr(m, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
