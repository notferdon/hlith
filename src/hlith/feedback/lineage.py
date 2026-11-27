# SPDX-License-Identifier: Apache-2.0
"""Causal lineage tracking for loaded and newly persisted L5 feedback."""

from __future__ import annotations

from dataclasses import dataclass

from ..contract.feedback import FeedbackInput
from ..contract.identities import RunId, Sha256


@dataclass(frozen=True)
class FeedbackLineage:
    """Provenance summary connecting a run's ``FeedbackInput`` to prior runs."""

    input_sha256: Sha256
    loaded_record_ids: tuple[str, ...]
    source_run_ids: tuple[RunId, ...]
    record_sources: tuple[tuple[str, RunId], ...]


def build_lineage(feedback_input: FeedbackInput) -> FeedbackLineage:
    """Extract deterministic lineage metadata from a validated ``FeedbackInput``."""
    pairs = tuple(sorted({(r.record_id, r.source_run_id) for r in feedback_input.records}))
    loaded_ids = tuple(sorted({r.record_id for r in feedback_input.records}))
    return FeedbackLineage(
        input_sha256=feedback_input.input_sha256,
        loaded_record_ids=loaded_ids,
        source_run_ids=feedback_input.lineage,
        record_sources=pairs,
    )
