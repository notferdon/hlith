"""case (sys.set_int_max_str_digits): process-wide interpreter state a target can change for every later call and StateWatch._proc_state did not
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


# ---- sys.set_int_max_str_digits ----
def test_int_max_str_digits_changed_by_the_call_is_reported_and_restored():
    orig = sys.get_int_max_str_digits()
    try:
        seen = _watch_and_run(lambda: sys.set_int_max_str_digits(700))
        assert "int_max_str_digits" in seen and "700" in seen, seen
        assert sys.get_int_max_str_digits() == orig
    finally:
        sys.set_int_max_str_digits(orig)


def test_setting_the_same_int_max_str_digits_is_not_a_difference():
    cur = sys.get_int_max_str_digits()
    assert _watch_and_run(lambda: sys.set_int_max_str_digits(cur)) == ""


def test_restore_false_reports_relative_to_construction_and_restore_true_resets_each_call():
    """design review n1pp / review review of a recorded review (b4546aec, point (2) later RETRACTED by review 27b08993): restore=False is the entrypoint recorder
    (differential.py ~7633); by contract it LEAVES the state and reports relative to construction, like self.rl and every other
    _proc_state key, so an untouched second call repeats the first call's line. That contract is pinned here, together with the
    restore=True half of the control: the limit is back to its original value after EACH call."""
    orig = sys.get_int_max_str_digits()
    try:
        mod = types.ModuleType("n1_imd_norestore")
        mod.f = lambda: 1
        w = _StateWatch(mod, mod.f)
        sys.set_int_max_str_digits(700)
        first = w.changes_and_restore(dict(os.environ), restore=False)
        second = w.changes_and_restore(dict(os.environ), restore=False)  # touches nothing
        assert "int_max_str_digits" in first and "700" in first, first
        assert second == first, (first, second)  # relative to construction: the documented recorder contract
        assert sys.get_int_max_str_digits() == 700  # restore=False leaves it, by design
        sys.set_int_max_str_digits(orig)
        w2 = _StateWatch(types.ModuleType("n1_imd_restore"), mod.f)
        for _ in range(2):
            sys.set_int_max_str_digits(700)
            seen = w2.changes_and_restore(dict(os.environ), restore=True)
            assert "700" in seen and sys.get_int_max_str_digits() == orig, seen
        assert w2.changes_and_restore(dict(os.environ), restore=True) == ""  # an untouched call under restore=True is silent
    finally:
        sys.set_int_max_str_digits(orig)
