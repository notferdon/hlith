# SPDX-License-Identifier: Apache-2.0
"""Per-stage work accounting for a case .

Four stages, each with its OWN budget of work units: generation (candidate inputs), replay (running them), instrumentation
(building the observed copies) and test_execution (repository tests). A stage cannot spend more than its share and cannot spend
another stage's share, so one stage cannot burn the case deadline; an exhausted stage is an explicit record, never silence.
Units are what the stage's meter reports (the driver's rlimit meter, evaluation counts): no wall clock, so the same charges give the
same report. The ledger measures and limits; it decides nothing about verdicts."""

from __future__ import annotations

from contextlib import contextmanager

STAGES = ("generation", "replay", "instrumentation", "test_execution")


class StageExhausted(RuntimeError):
    """The stage reached its budget. The charge that crossed it is recorded up to the budget; the stage must stop."""


class PhaseLedger:
    def __init__(self, total: float, shares: dict[str, float]):
        if set(shares) != set(STAGES):
            raise ValueError(f"shares must name exactly {STAGES}")
        if any(v < 0 for v in shares.values()) or sum(shares.values()) > total:
            raise ValueError("stage shares must be non-negative and sum to at most the total")
        self.total = total
        self._budget = dict(shares)
        self._used = {s: 0 for s in STAGES}
        self._state = {s: "not_run" for s in STAGES}
        self._reason = {s: "" for s in STAGES}
        self._current: str | None = None

    def _check(self, stage: str) -> None:
        if stage not in STAGES:
            raise ValueError(f"unknown stage {stage!r}")

    @contextmanager
    def stage(self, name: str):
        self._check(name)
        if self._current is not None:
            raise ValueError("stages do not nest: one meter at a time")
        self._current = name
        if self._state[name] == "not_run":
            self._state[name] = "ok"
        try:
            yield self
        finally:
            self._current = None

    def remaining(self, stage: str) -> float:
        """What this stage may still spend: its own share left, never more than the total left."""
        self._check(stage)
        total_left = self.total - sum(self._used.values())
        return max(0, min(self._budget[stage] - self._used[stage], total_left))

    def charge(self, stage: str, units: float) -> None:
        self._check(stage)
        if units < 0:
            raise ValueError("work units cannot be negative")
        room = self.remaining(stage)
        if units > room:
            self._used[stage] += room  # recorded up to the budget, never beyond
            self._state[stage] = "exhausted"
            self._reason[stage] = f"stage budget of {self._budget[stage]} work units reached"
            raise StageExhausted(f"{stage}: {self._reason[stage]}")
        self._used[stage] += units
        if self._state[stage] == "not_run":
            self._state[stage] = "ok"

    def skip(self, stage: str, reason: str) -> None:
        self._check(stage)
        self._state[stage] = "skipped"
        self._reason[stage] = reason

    def report(self) -> list[dict]:
        return [{"stage": s, "budget": self._budget[s], "used": self._used[s], "state": self._state[s], "reason": self._reason[s]}
                for s in STAGES]
