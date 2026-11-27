# SPDX-License-Identifier: Apache-2.0
"""Closed verdict domain and the invariants that make a verdict hard to fake.

Design corrections applied here (maintainer steering 2026-11-11):
  * ``held`` is a bounded statement. It carries the executions run, the input
    domain actually explored and the scope NOT explored. It never means
    universal correctness.
  * Independence is a recorded process fact (``CheckProvenance``), not a boolean
    the proposer can set.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field


class Verdict(str, enum.Enum):
    HELD = "held"
    REFUTED = "refuted"
    NOT_DERIVED = "not-derived"
    UNVERIFIED = "unverified"


class GateOutcome(str, enum.Enum):
    LANDED = "landed"
    REFUSED = "refused"


EXIT_LANDED = 0
EXIT_REFUTED = 10
EXIT_NOT_DERIVED = 11
EXIT_UNVERIFIED = 12
EXIT_BOUNDARY = 4


@dataclass(frozen=True)
class CheckProvenance:
    """How a check ran. Filled by the supervisor, never by the proposer."""

    checker_id: str
    checker_sha256: str  # digest of the checker code that ran
    confined: bool  # ran under the kernel confinement profile
    proposer_paths_readable: bool  # False only if profile denied proposer dirs
    profile_sha256: str  # digest of the confinement profile used
    exit_code: int


@dataclass(frozen=True)
class BoundedEvidence:
    executions: int
    explored: str  # what input domain / call sites were exercised
    unexplored: str  # what was NOT exercised; must be non-empty

    def __post_init__(self) -> None:
        if self.executions < 1:
            raise ValueError("bounded evidence needs >= 1 execution")
        if not self.explored.strip() or not self.unexplored.strip():
            raise ValueError("evidence must state both explored and unexplored scope")


@dataclass(frozen=True)
class Obligation:
    obligation_id: str
    target_symbol: str
    claim: str
    verdict: Verdict
    evidence: BoundedEvidence | None = None
    provenance: CheckProvenance | None = None
    witness: str | None = None
    stop_reason: str | None = None
    # Hlith.md 0.2: the gate needs >= 1 held obligation that consumed the effect account. True only for
    # obligations derived from the account's claims (binding, differential, constant/reader, guard coverage),
    # never for feedback-only or proposer-only claims.
    account_bound: bool = False

    def __post_init__(self) -> None:
        if self.verdict is Verdict.HELD:
            if self.evidence is None or self.provenance is None:
                raise ValueError("held requires bounded evidence and check provenance")
            p = self.provenance
            if not p.confined or p.proposer_paths_readable or p.exit_code != 0:
                raise ValueError("held requires a confined, proposer-blind, clean check")
        if self.verdict is Verdict.REFUTED and not self.witness:
            raise ValueError("refuted requires a witness")
        if self.verdict in (Verdict.NOT_DERIVED, Verdict.UNVERIFIED) and not self.stop_reason:
            raise ValueError(f"{self.verdict.value} requires a stop reason")


@dataclass(frozen=True)
class ObligationSet:
    obligations: tuple[Obligation, ...]
    # Non-gating proof evidence (e.g. delta_rel items). decide() never reads it: it cannot make a set land.
    evidence: tuple[dict, ...] = ()

    def __post_init__(self) -> None:
        if len(self.obligations) < 1:
            raise ValueError("Empty obligation set is forbidden")


@dataclass(frozen=True)
class ProposedEffect:
    unified_diff: str
    proposer_id: str
    touched_files: tuple[str, ...] = field(default=())

    @property
    def patch_sha256(self) -> str:
        return hashlib.sha256(self.unified_diff.encode()).hexdigest()


@dataclass(frozen=True)
class GateDecision:
    outcome: GateOutcome
    exit_status: int
    blocking: tuple[str, ...] = ()
    landed_commit: str | None = None


def decide(obligations: ObligationSet) -> GateDecision:
    """Pure verdict-lattice decision. Landing needs every obligation held."""
    vs = [o.verdict for o in obligations.obligations]
    if all(v is Verdict.HELD for v in vs):
        if not any(o.account_bound for o in obligations.obligations):
            return GateDecision(GateOutcome.REFUSED, EXIT_NOT_DERIVED, ("no-account-bound-obligation",))
        return GateDecision(GateOutcome.LANDED, EXIT_LANDED)
    blocking = tuple(o.obligation_id for o in obligations.obligations if o.verdict is not Verdict.HELD)
    for v, code in (
        (Verdict.REFUTED, EXIT_REFUTED),
        (Verdict.NOT_DERIVED, EXIT_NOT_DERIVED),
        (Verdict.UNVERIFIED, EXIT_UNVERIFIED),
    ):
        if v in vs:
            return GateDecision(GateOutcome.REFUSED, code, blocking)
    raise AssertionError("unreachable: closed verdict domain")
