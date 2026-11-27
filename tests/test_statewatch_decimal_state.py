"""case (decimal flags/traps): process-wide interpreter state a target can change for every later call and StateWatch._proc_state did not
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


# ---- decimal sticky flags ----
def test_decimal_flags_set_by_the_call_are_reported_and_restored():
    ctx = decimal.getcontext()
    ctx.clear_flags()
    seen = _watch_and_run(lambda: decimal.Decimal(1) / decimal.Decimal(3))
    assert "decimal context" in seen and "Inexact" in seen, seen
    assert not any(ctx.flags.values()), "sticky flags must be restored to the baseline"


def test_decimal_trap_changed_by_the_call_is_reported_and_restored():
    ctx = decimal.getcontext()
    before = ctx.traps[decimal.Inexact]
    try:
        seen = _watch_and_run(lambda: ctx.traps.__setitem__(decimal.Inexact, not before))
        assert "decimal context" in seen and "Inexact" in seen, seen
        assert ctx.traps[decimal.Inexact] == before
    finally:
        ctx.traps[decimal.Inexact] = before


def test_exact_decimal_arithmetic_is_not_a_difference():
    decimal.getcontext().clear_flags()
    assert _watch_and_run(lambda: decimal.Decimal(1) + decimal.Decimal(1)) == ""
