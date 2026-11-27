"""case (gc.callbacks): process-wide interpreter state a target can change for every later call and StateWatch._proc_state did not
observe (recorded review lead; 3-line probe on root 6ab00d0f gave an empty change string). RED test + CONTROL."""
import decimal
import gc
import importlib.util
import os
import sys
import types

import pytest

from hlith.differential import _StateWatch


def _watch_and_run(mutate, tree_root=None):
    mod = types.ModuleType("n1_proc")
    mod.f = lambda: 1
    w = _StateWatch(mod, mod.f, tree_root=tree_root)
    mutate()
    return w.changes_and_restore(dict(os.environ))


# ---- gc.callbacks ----
def _cb(phase, info):
    return None


def test_gc_callback_added_by_the_call_is_reported_and_removed():
    before = list(gc.callbacks)
    try:
        seen = _watch_and_run(lambda: gc.callbacks.append(_cb))
        assert "gc callbacks" in seen and "_cb" in seen, seen
        assert list(gc.callbacks) == before
    finally:
        gc.callbacks[:] = before


def test_gc_callback_added_and_removed_in_the_same_call_is_not_a_difference():
    def churn():
        gc.callbacks.append(_cb)
        gc.callbacks.remove(_cb)
    assert _watch_and_run(churn) == ""


def test_the_same_gc_callback_from_two_trees_compares_equal_and_different_code_does_not(tmp_path):
    def load(side, body):
        p = tmp_path / side / "gcmod.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"def cb(phase, info):\n    return {body!r}\n")
        spec = importlib.util.spec_from_file_location(f"gcmod_{side}", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m, str(tmp_path / side)
    ma, ra = load("base", "same")
    mb, rb = load("post", "same")
    mc, rc = load("other", "different")
    before = list(gc.callbacks)
    try:
        a = _watch_and_run(lambda: gc.callbacks.append(ma.cb), tree_root=ra)
        gc.callbacks[:] = before
        b = _watch_and_run(lambda: gc.callbacks.append(mb.cb), tree_root=rb)
        gc.callbacks[:] = before
        c = _watch_and_run(lambda: gc.callbacks.append(mc.cb), tree_root=rc)
    finally:
        gc.callbacks[:] = before
    assert a == b and a != "", (a, b)
    assert a != c, (a, c)
