# SPDX-License-Identifier: Apache-2.0
"""A divergence confirmed on a synthetic stand-in is DEFERRED by witness selection (check() returns None, case) and
only converted into the witness after the target loop. When the exploration budget is spent first, the budget block sets
out["unverified"] BEFORE that conversion, and emit() then returns UNVERIFIED although a divergence was confirmed: a missed refutation
(fail-safe direction, never a false HELD). review's 2026-11-15 18:04 P2 finding (case) located the same family at the
supervisor wall cap (_save_partial never sees a deferred divergence); this is the cheaper, deterministic in-budget variant.

Source pin: root 6ab00d0f, src/hlith/differential.py: budget block ~10168-10172 sets out["unverified"] when `not witness`; the deferred
conversion `if not collect and not witness and cands_w_` follows at ~10178-10182; `if out.get("unverified"): emit(out); return` at ~10212.
Read-only audit + falsifier by review; no change to differential.py is made here (review/review own it)."""
import pytest

from hlith import differential
from hlith.types import Verdict

_REACH = "import pkg.m as m\n\n\ndef test_reach():\n    m.f\n"
_STUB = {"$obj": {"methods": {}, "attrs": {}}}


def _src(trigger: str, ret: int, slow: bool = True) -> str:
    # slow: every call burns 0.4 s so a small explore_budget is spent early; only the trigger input diverges
    nap = "    time.sleep(0.4)\n" if slow else ""
    return f"import time\n\n\ndef f(x):\n{nap}    if {trigger}:\n        return {ret}\n    return 0\n"


def _run(tmp_path, trigger: str, seed, slow: bool = True, **kw):
    for side, ret in (("base", 1), ("post", 2)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(_src(trigger, ret, slow))
        (tmp_path / side / "test_reach.py").write_text(_REACH)
    (tmp_path / "proposer").mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=50, max_examples=5,
        seeds=[seed], timeout=60, **kw)


def test_budget_spent_after_a_real_value_divergence_still_refutes(tmp_path):
    """NEGATIVE CONTROL (passes today): the same shape with a divergence on a real value is REFUTED even though the budget is spent."""
    ob = _run(tmp_path, "x == 5", ([5], {}, "trigger"), explore_budget=4.0)
    assert ob.verdict is Verdict.REFUTED, ob


def test_stand_in_divergence_without_budget_pressure_is_refuted(tmp_path):
    """CONTROL (passes today): the stand-in divergence IS confirmable; with no budget pressure the end-of-loop conversion refutes it."""
    ob = _run(tmp_path, 'type(x).__name__ == "Stub"', ([_STUB], {}, "trigger"), slow=False)
    assert ob.verdict is Verdict.REFUTED, ob


def test_stand_in_divergence_survives_a_spent_exploration_budget(tmp_path):
    ob = _run(tmp_path, 'type(x).__name__ == "Stub"', ([_STUB], {}, "trigger"), explore_budget=4.0)
    assert ob.verdict is Verdict.REFUTED, ob
