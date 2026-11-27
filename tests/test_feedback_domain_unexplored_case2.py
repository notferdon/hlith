# SPDX-License-Identifier: Apache-2.0
"""review, design review 2026-11-21 (the one F2 route): a landing's domain record prefers inputs the GATE never ran.
Measured on counterpatch: largest-first picked only inputs the engine's own exploration already dominates. The gate's explored-input
summary (review differential.read_explored_inputs) now orders the candidates by review's decision rule: a value was NOT run iff
explored_input_digest(value) is absent from params[i].digests AND not digests_truncated. The 64-entry values[] sample never decides
absence (F2b shape: 402 distinct, 64 values, 402 digests). Unusable summary = UNKNOWN = the old order (never "nothing explored")."""
from __future__ import annotations

import pytest

from hlith.differential import explored_input_digest, explored_input_key

SYM = "pkg.m.f"
BIG = ["a" * n for n in range(9000, 9020)]  # 20 large inputs: largest-first takes 16 of them and never "zz"


def _agreeing():
    return [{"args": [s], "kwargs": {}} for s in BIG] + [{"args": ["zz"], "kwargs": {}}, {"args": ["tests/x"], "kwargs": {}}]


def _summary(ran, *, digests_truncated=False, digests=True, target=SYM, sample=64):
    p = {"name": "path", "annotation": "str", "distinct": len(ran), "truncated": len(ran) > sample,
         "values": [{"key": explored_input_key(v), "type": "str", "admitted": True} for v in ran[:sample]]}
    if digests:
        p.update(digests=sorted(explored_input_digest(v) for v in ran), digests_truncated=digests_truncated)
    return {"target": target, "calls": len(ran), "truncated": len(ran) > sample, "params": [p]}


def _picked(rec):
    return [i["args"][0] for i in rec.directive_payload["pinned_inputs"]]


def _pick(explored, notes=None):
    from hlith.feedback.probe import domain_constraint_from_agreeing
    return _picked(domain_constraint_from_agreeing("run-0123456789ab", SYM, _agreeing(), explored=explored, explored_notes=notes))


def test_novelty_order_differs_from_largest_first_via_digests():
    # F2b shape: the gate ran MORE distinct values than the 64-entry sample shows (sample truncated), digests complete.
    filler = [f"f{i}" for i in range(100)]
    explored = _summary(filler + BIG + ["tests/x"])  # everything but "zz"; BIG and "tests/x" are only visible through digests
    notes: list[str] = []
    got = _pick(explored, notes)
    assert got[0] == "zz" and len(got) == 16 and not notes, (got[:3], notes)
    assert _pick(None)[0] == "a" * 9019 and "zz" not in _pick(None)  # the old order would never pick it


def test_digests_truncated_or_absent_is_unknown():
    for bad in (_summary(BIG + ["tests/x"], digests_truncated=True), _summary(BIG + ["tests/x"], digests=False)):
        notes: list[str] = []
        got = _pick(bad, notes)
        assert got[0] == "a" * 9019 and "zz" not in got, got[:2]  # absence proves nothing: no novelty
        assert any("no parameter has a complete explored-digest set" in n for n in notes), notes


def test_other_target_is_unknown():
    notes: list[str] = []
    assert _pick(_summary(BIG, target="pkg.m.other"), notes)[0] == "a" * 9019
    assert any("another target" in n for n in notes), notes


def test_no_summary_keeps_largest_first():
    got = _pick(None)
    assert "zz" not in got and got[0] == "a" * 9019


def test_landing_context_carries_the_summary():
    from hlith.feedback import LandingProbeContext
    assert LandingProbeContext.__dataclass_fields__["gate_explored"].default_factory() == {}
