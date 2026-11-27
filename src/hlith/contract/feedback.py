# SPDX-License-Identifier: Apache-2.0
"""L5 -> L2/L3 contract: an immutable, validated, ADD-ONLY input. A removal is not representable."""

from __future__ import annotations

from dataclasses import dataclass

from .codec import sha256_canonical
from .effects import Unknown
from .identities import RunId, Sha256


@dataclass(frozen=True)
class FeedbackRecordRef:
    record_id: str
    source_run_id: RunId
    symbol: str
    kind: str  # e.g. pin_regression_counterexample, not_derived_construct
    sha256: Sha256


@dataclass(frozen=True)
class FeedbackInput:
    records: tuple[FeedbackRecordRef, ...] = ()
    extra_unknowns: tuple[Unknown, ...] = ()
    extra_callers: tuple[str, ...] = ()
    seeds: tuple[tuple[str, str], ...] = ()  # (symbol, canonical input json)
    pins: tuple[tuple[str, str, str], ...] = ()  # (symbol, canonical input json, expected canonical output)
    # (where, construct_kind, node_sha256, feedback_id) of stored NOT_DERIVED constructs (design plan). NOT unknowns by themselves:
    # L3 blocks on one only while the LIVE account still has an unresolved construct with that node_sha256 at that place, so a
    # fix-then-retry in the same state dir is decided on the live code instead of a permanent stored unknown.
    constructs: tuple[tuple[str, str, str, str], ...] = ()
    # Symbol, canonical input, expected output (empty for a seed), source record id.
    input_sources: tuple[tuple[str, str, str, str], ...] = ()

    @property
    def input_sha256(self) -> Sha256:
        return Sha256(sha256_canonical(self))

    @property
    def lineage(self) -> tuple[RunId, ...]:
        return tuple(sorted({r.source_run_id for r in self.records}))


EMPTY_FEEDBACK = FeedbackInput()
