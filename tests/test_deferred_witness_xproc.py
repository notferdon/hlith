# SPDX-License-Identifier: Apache-2.0
"""Attack on 4fd94364 (review, case): the early conversion of a deferred stand-in divergence is skipped when
xproc_nondet_ is set (`... and cands_w_ and not xproc_nondet_`, differential.py ~10168). A deferred candidate has ALREADY passed its
own process-dependence replay (the replay at ~8815-8845 returns None for a process-dependent divergence BEFORE the deferral at
~8861), so the guard drops a confirmed deterministic divergence because an UNRELATED divergence elsewhere is process-dependent.
Asymmetry measured on 4fd94364: an ordinary-value divergence + the same unrelated pid divergence is REFUTED (control), while the
stand-in divergence + that pid divergence is UNVERIFIED 'nondeterminism across processes'. Missed refutation (fail-safe, never HELD).
Fix shape: drop `and not xproc_nondet_` from the early conversion (the candidate is individually replay-confirmed); the original
later conversion then stays the only path for the case where unverified was already set for another reason."""
import pytest

from hlith import differential
from hlith.types import Verdict

_REACH = "import pkg.m as m\n\n\ndef test_reach():\n    m.f\n"
_STUB = {"$obj": {"methods": {}, "attrs": {}}}


def _src(post: bool, divergence: str) -> str:
    # x == 7: base returns the pid (different in every process: a process-dependent divergence of class ret/exc), post raises.
    pid = "        raise ValueError('p')\n" if post else "        return os.getpid()\n"
    ret = 2 if post else 1
    return f"import os\n\n\ndef f(x):\n    if x == 7:\n{pid}    if {divergence}:\n        return {ret}\n    return 0\n"


def _run(tmp_path, divergence: str, seeds):
    for side, post in (("base", False), ("post", True)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(_src(post, divergence))
        (tmp_path / side / "test_reach.py").write_text(_REACH)
    (tmp_path / "proposer").mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=50, max_examples=5,
        seeds=seeds, timeout=60)


def test_ordinary_divergence_survives_an_unrelated_process_dependent_one(tmp_path):
    """CONTROL (passes today)."""
    ob = _run(tmp_path, "x == 5", [([5], {}, "real"), ([7], {}, "pid")])
    assert ob.verdict is Verdict.REFUTED, ob


def test_stand_in_divergence_survives_an_unrelated_process_dependent_one(tmp_path):
    ob = _run(tmp_path, "type(x).__name__ == 'Stub'", [([_STUB], {}, "stub"), ([7], {}, "pid")])
    assert ob.verdict is Verdict.REFUTED, ob
