# SPDX-License-Identifier: Apache-2.0
"""Run lifecycle contract shared by every surface."""

from __future__ import annotations

import enum
from dataclasses import dataclass

from .identities import InvocationId, RunId, Sha256, ThreadId


class RunMode(str, enum.Enum):
    STANDALONE = "standalone"
    COMPANION = "companion"
    HEADLESS = "headless"


class LandingTarget(str, enum.Enum):
    ORIGINAL = "original"  # the user's repository
    REHEARSAL = "rehearsal"  # a disposable clone: NEVER reported as an original-target landing


@dataclass(frozen=True)
class RunReceipt:
    run_id: RunId  # allocated by the engine coordinator only
    invocation_id: InvocationId  # the surface's own id, LINKED to run_id
    thread_id: ThreadId | None
    mode: RunMode
    landing_target: LandingTarget


@dataclass(frozen=True)
class GateReceipt:
    run_id: RunId
    outcome: str  # "landed" | "refused"
    exit_status: int
    blocking: tuple[str, ...]
    landed_commit: str | None
    verification_record_sha256: Sha256 | None
