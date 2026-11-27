# SPDX-License-Identifier: Apache-2.0
"""delta_rel.check_callable (numeric + UF mode) and guard_removed.removed_entry_guards run in the same forked,
confined, resource-limited worker as the driver, with rlimit budgets instead of wall timeouts. A killed or failed
call is a NAMED STOP: delta_rel => UNMODELED (never PROVED), guard_removed => None (could not be decided).
Same inputs => same evidence artifact whatever the load or history."""
import json
import os
import threading

import pytest
import z3

from hlith import delta_rel, drive_inputs as D, guard_removed

BASE = "def f(x: int) -> int:\n    return x + 1\n"
EQUIV = "def f(x: int) -> int:\n    return 1 + x\n"
DIFF = "def f(x: int) -> int:\n    return x + 2\n"
UF_BASE = "def g(s):\n    return helper(s) + 1\n"
UF_POST = "def g(s):\n    return 1 + helper(s)\n"
GR_BASE = "def f(x: int):\n    if x < 0:\n        raise ValueError('neg')\n    if x > 100:\n        raise ValueError('big')\n    return x\n"
GR_DROP = "def f(x: int):\n    if x < 0:\n        raise ValueError('neg')\n    return x\n"
GR_REORDER = "def f(x: int):\n    if x > 100:\n        raise ValueError('big')\n    if x < 0:\n        raise ValueError('neg')\n    return x\n"


def _norm(r):
    return json.dumps(r.to_dict() if hasattr(r, "to_dict") else r, sort_keys=True)


def test_signatures_are_unchanged_and_inproc_twins_exist():
    import inspect

    assert inspect.signature(delta_rel.check_callable) == inspect.signature(delta_rel._check_callable_inproc)
    assert inspect.signature(guard_removed.removed_entry_guards) == inspect.signature(guard_removed._removed_entry_guards_inproc)


def test_delta_rel_sandboxed_verdicts_equal_the_in_process_ones():
    for base, post, verdict in ((BASE, EQUIV, "PROVED"), (BASE, DIFF, "COUNTEREXAMPLE")):
        got = delta_rel.check_callable(base, post, "f")
        ref = delta_rel._check_callable_inproc(base, post, "f")
        assert got.verdict == verdict == ref.verdict, (got, ref)
        assert got.tier == ref.tier and got.reason == ref.reason
        assert got.witness_inputs == ref.witness_inputs
    uf = delta_rel.check_callable(UF_BASE, UF_POST, "g")
    ref = delta_rel._check_callable_inproc(UF_BASE, UF_POST, "g")
    assert (uf.verdict, uf.tier) == (ref.verdict, ref.tier), (uf, ref)


def test_guard_removed_sandboxed_equals_in_process():
    for post in (GR_DROP, GR_REORDER, GR_BASE):
        got = guard_removed.removed_entry_guards(GR_BASE, post, "f")
        ref = guard_removed._removed_entry_guards_inproc(GR_BASE, post, "f")
        assert got == ref, (post, got, ref)
    assert [g["cond"] for g in guard_removed.removed_entry_guards(GR_BASE, GR_DROP, "f")] == ["x > 100"]


def test_a_killed_delta_rel_call_is_unmodeled_and_never_proved(monkeypatch):
    monkeypatch.setitem(D.SANDBOX_LIMITS, "wall_s", 0.001)
    r = delta_rel.check_callable(BASE, EQUIV, "f")
    assert r.verdict == delta_rel.UNMODELED and r.tier == "none" and r.verdict != delta_rel.PROVED, r
    assert "sandbox" in r.reason and r.witness_inputs == [] and r.provenance["function"] == "f", r
    monkeypatch.undo()
    assert delta_rel.check_callable(BASE, EQUIV, "f").verdict == delta_rel.PROVED  # next call unaffected


def test_a_killed_guard_removed_call_is_undecided_not_clean(monkeypatch):
    monkeypatch.setitem(D.SANDBOX_LIMITS, "wall_s", 0.001)
    assert guard_removed.removed_entry_guards(GR_BASE, GR_DROP, "f") is None  # None = could not be decided (blocks)
    assert "sandbox" in guard_removed.last_stop()
    monkeypatch.undo()
    assert guard_removed.removed_entry_guards(GR_BASE, GR_DROP, "f")


def test_every_solver_in_these_modules_is_bounded_by_rlimit_not_only_wall_time():
    seen = {}
    orig_set, orig_check = z3.Solver.set, z3.Solver.check

    def set_(self, *a, **kw):
        seen.setdefault(id(self), set()).update(a[:1] if a else kw.keys())
        return orig_set(self, *a, **kw)

    def check(self, *a):
        seen.setdefault(id(self), set())
        unbounded.append(id(self)) if "rlimit" not in seen[id(self)] else None
        return orig_check(self, *a)

    unbounded: list[int] = []
    z3.Solver.set, z3.Solver.check = set_, check
    try:
        delta_rel._check_callable_inproc(BASE, EQUIV, "f")
        delta_rel._check_callable_inproc(BASE, DIFF, "f")
        delta_rel._check_callable_inproc(UF_BASE, UF_POST, "g")
        guard_removed._removed_entry_guards_inproc(GR_BASE, GR_DROP, "f")
        guard_removed._removed_entry_guards_inproc(GR_BASE, GR_REORDER, "f")
    finally:
        z3.Solver.set, z3.Solver.check = orig_set, orig_check
    assert not unbounded, f"{len(unbounded)} solver check(s) ran without an rlimit budget"


def test_same_inputs_same_evidence_artifact_under_load_and_history():
    stop = threading.Event()

    def burn():
        while not stop.is_set():
            sum(i * i for i in range(20000))

    ts = [threading.Thread(target=burn, daemon=True) for _ in range(4)]
    for t in ts:
        t.start()
    try:
        cases = [(BASE, EQUIV, "f"), (BASE, DIFF, "f"), (UF_BASE, UF_POST, "g")]
        ref = [_norm(delta_rel.check_callable(*c)) for c in cases]
        gref = json.dumps(guard_removed.removed_entry_guards(GR_BASE, GR_DROP, "f"), sort_keys=True)
        for i in range(10):
            # unrelated in-process z3 history between calls
            D._candidates_detailed_inproc([("q", "int")], ["q % 7 == 3 and q > 100"], want="both")
            for c, r in zip(cases, ref):
                assert _norm(delta_rel.check_callable(*c)) == r, (i, c)
            assert json.dumps(guard_removed.removed_entry_guards(GR_BASE, GR_DROP, "f"), sort_keys=True) == gref
    finally:
        stop.set()


def test_two_independent_processes_give_the_same_artifact():
    import subprocess
    import sys

    src = os.path.dirname(os.path.dirname(D.__file__))
    script = (
        "import json, sys\n"
        f"sys.path.insert(0, {src!r})\n"
        "from hlith import delta_rel, guard_removed, drive_inputs as D\n"
        "BASE, EQUIV, DIFF = json.loads(sys.argv[1])\n"
        "if sys.argv[2] == '1':\n"
        "    D._candidates_detailed_inproc([('q', 'int')], ['q % 7 == 3 and q > 100'], want='both')\n"
        "a = delta_rel.check_callable(BASE, EQUIV, 'f').to_dict()\n"
        "b = delta_rel.check_callable(BASE, DIFF, 'f').to_dict()\n"
        "print('RESULT' + json.dumps([a, b], sort_keys=True))\n")

    def run(pollute):
        cp = subprocess.run([sys.executable, "-I", "-c", script, json.dumps([BASE, EQUIV, DIFF]), pollute], capture_output=True,
                            text=True, timeout=300)
        assert cp.returncode == 0, cp.stderr[-800:]
        return json.loads(cp.stdout.split("RESULT", 1)[1])

    assert run("0") == run("1")


def test_the_worker_preloaded_the_z3_modules_so_children_start_from_one_image():
    D.sandbox_selftest()
    pre = D._SB["info"]["preload"]
    assert pre == {"delta_rel": True, "delta_rel_uf": True, "guard_removed": True}, pre


def test_the_repo_universe_argument_crosses_the_sandbox_and_sets_the_tier():
    clean = {"subclasses": [], "complete": True}
    r = delta_rel.check_callable(BASE, EQUIV, "f", None, None, clean)
    ref = delta_rel._check_callable_inproc(BASE, EQUIV, "f", None, None, clean)
    assert (r.verdict, r.tier, r.assumptions) == (ref.verdict, ref.tier, ref.assumptions) == ("PROVED", "unconditional", [])
    unknown = delta_rel.check_callable(BASE, EQUIV, "f")
    assert unknown.verdict == "PROVED" and unknown.tier == "conditional" and unknown.assumptions
    dirty = delta_rel.check_callable(BASE, EQUIV, "f", None, None, {"subclasses": ["I(int)"], "complete": True})
    assert dirty.verdict == delta_rel.UNMODELED


def test_set_d_through_the_sandbox_is_still_never_an_unconditional_proof():
    from test_delta_rel_soundness import D as SET_D

    for name, (base, post, _call) in SET_D.items():
        r = delta_rel.check_callable(base, post, "f", [], None, {"subclasses": [], "complete": True})
        assert not (r.verdict == delta_rel.PROVED and r.tier == "unconditional"), (name, r)
