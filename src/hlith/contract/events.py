# SPDX-License-Identifier: Apache-2.0
"""Progress/decision event contract. Progress can never impersonate a verdict."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

from .identities import RunId


class Phase(str, enum.Enum):
    RUNTIME = "runtime"
    EFFECT = "effect"
    OBLIGATION = "obligation"
    GATE = "gate"
    FEEDBACK = "feedback"


class EventKind(str, enum.Enum):
    PHASE_STARTED = "phase_started"
    PHASE_FINISHED = "phase_finished"
    PROGRESS = "progress"
    ARTIFACT_WRITTEN = "artifact_written"
    DECISION = "decision"  # emitted only from the gate receipt


@dataclass(frozen=True)
class Event:
    run_id: RunId
    seq: int
    kind: EventKind
    phase: Phase | None
    ts: str  # UTC ISO-8601
    detail: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind is not EventKind.DECISION and any(k in self.detail for k in ("verdict", "outcome", "exit_status")):
            raise ValueError("only a DECISION event may carry a verdict, outcome or exit status")
