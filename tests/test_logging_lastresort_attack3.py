"""case round 3 (review attack on review's 2b1e0037; regression file, included here). Restore now runs on EVERY watched call:
  P  QUADRATIC COST: _logging_restore calls Logger.setLevel for every logger (and root) even when nothing changed; CPython's
     setLevel calls manager._clear_cache(), which walks ALL loggers, so an untouched watched call is O(loggers^2): 1000 loggers with
     a stdlib handler 115.6 ms per call (root/bc0d72ad ~5 ms). With hundreds of executions per obligation that eats the evaluator
     deadline (HELD -> UNVERIFIED by timeout). Deterministic check: cache clears on an untouched call.
  N  NOISE: a handler already in the tree that cannot be written back (blocked __setattr__, a stream property returning a new object,
     a __slots__ duck handler) makes EVERY untouched call report 'logging state unrestorable' (root/bc0d72ad: nothing).
"""
import logging
import os
import sys
import types

import pytest

from hlith import differential


def _watch(fn):
    mod = types.ModuleType("n2_m1o_a3")
    mod.f = fn
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    return w.changes_and_restore(dict(os.environ), restore=True)


def _untouched(n):
    return n


@pytest.fixture
def many_loggers():
    made = []
    for i in range(300):
        lg = logging.getLogger(f"test.a3.{i:03d}")
        h = logging.StreamHandler(sys.stderr)
        lg.addHandler(h)
        made.append((lg, h))
    yield made
    for lg, h in made:
        lg.removeHandler(h)
    for i in range(300):
        logging.root.manager.loggerDict.pop(f"test.a3.{i:03d}", None)


def test_P_untouched_call_does_not_clear_every_logger_cache(many_loggers, monkeypatch):
    calls = []
    orig = logging.Manager._clear_cache
    monkeypatch.setattr(logging.Manager, "_clear_cache", lambda self: (calls.append(1), orig(self))[1])
    _watch(_untouched)
    calls_untouched = len(calls)
    assert calls_untouched <= 2, f"an untouched watched call cleared the logger cache {calls_untouched} times (O(loggers^2))"


def test_P_changed_level_is_still_restored(many_loggers):
    """Control for the fix: skipping unchanged loggers must still restore a changed one."""
    lg = many_loggers[17][0]
    lg.setLevel(logging.WARNING)

    def f(n):
        lg.setLevel(logging.DEBUG)
        return n
    assert _watch(f) != _watch(_untouched)
    assert lg.level == logging.WARNING


class _Duck:
    __slots__ = ("level", "formatter", "filters")

    def __init__(self):
        self.level, self.formatter, self.filters = 0, None, []

    def handle(self, r):
        return True

    def setLevel(self, lvl):
        self.level = lvl


class _LyingStream(logging.Handler):
    @property
    def stream(self):
        import io
        return io.StringIO()


@pytest.mark.parametrize("make", [_Duck, _LyingStream], ids=["slots-duck", "lying-stream"])
def test_N_untouched_call_with_an_odd_preexisting_handler_reports_nothing(make):
    h = make()
    logging.getLogger().handlers.append(h)
    try:
        assert _watch(_untouched) == "", "nothing changed, yet the call reports a logging change"
    finally:
        logging.getLogger().handlers.remove(h)
