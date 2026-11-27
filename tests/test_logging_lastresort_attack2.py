"""case round 2 (review attack on review's fix bc0d72ad; regression file, included here). Root cause shared by most: restore runs
ONLY when a logging change was detected and was measurable (differential.py ~11744-11750: `if lg_rep:` and not
'unmeasurable'), and _StateWatch.__init__ takes _logging_cmp() unguarded (~11344).
  A  an instance-level emit/handle override on the ORIGINAL lastResort (one line in a patch) is neither seen nor restored
  B  a lastResort whose attribute access raises/recurses is reported 'unmeasurable' but never restored, so the NEXT watch's
     constructor raises (one call breaks measurement for the rest of the checker process)
  C  restore raising part-way (an instance setLevel on the original) skips every later restore step: named loggers keep the
     call's level and new loggers stay registered (reported 'unrestorable', but they leak into later calls)
  L  (named limit, documented, xfail): a same-qualname class with the same level/destination and a different emit
"""
import logging
import os
import sys
import types

import pytest

from hlith import differential

ORIG = logging.lastResort


@pytest.fixture(autouse=True)
def _clean():
    lg = logging.getLogger("test.m1o.after")
    lvl = lg.level
    yield
    logging.lastResort = ORIG
    for k in ("emit", "handle", "setLevel"):
        ORIG.__dict__.pop(k, None)
    lg.setLevel(lvl)
    logging.root.manager.loggerDict.pop("test.m1o.new", None)


def _watch(fn):
    mod = types.ModuleType("n2_m1o_a2")
    mod.f = fn
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    return w.changes_and_restore(dict(os.environ), restore=True)


def _untouched(n):
    return n


@pytest.mark.parametrize("attr", ["emit", "handle"])
def test_A_instance_override_on_original_last_resort_is_seen(attr):
    def f(n):
        setattr(ORIG, attr, lambda r: None)  # last-resort records silently dropped from now on
        return n
    assert _watch(f) != _watch(_untouched)


@pytest.mark.parametrize("attr", ["emit", "handle"])
def test_A_instance_override_on_original_last_resort_is_restored(attr):
    def f(n):
        setattr(ORIG, attr, lambda r: None)
        return n
    _watch(f)
    assert attr not in vars(ORIG), f"instance {attr} override leaked into later calls"


class _RaisingLevel(logging.Handler):
    @property
    def level(self):
        raise RuntimeError("boom level")

    @level.setter
    def level(self, v):
        pass


def test_B_unmeasurable_last_resort_is_still_restored():
    def f(n):
        logging.lastResort = _RaisingLevel()
        return n
    out = _watch(f)
    assert "unmeasurable" in out or out != _watch(_untouched)
    assert logging.lastResort is ORIG, "an unmeasurable lastResort stayed installed for later calls"


def test_B_next_watch_survives_a_hostile_last_resort():
    """Even if some state cannot be restored, the next call's watch must not crash in its constructor."""
    logging.lastResort = _RaisingLevel()
    mod = types.ModuleType("n2_m1o_a2b")
    mod.f = _untouched
    differential._StateWatch(mod, _untouched, None, None)  # must not raise


def test_C_restore_continues_after_a_failing_step():
    lg = logging.getLogger("test.m1o.after")
    lg.setLevel(logging.WARNING)

    def f(n):
        ORIG.setLevel = lambda *a: 1 / 0  # the lastResort restore step raises
        lg.setLevel(logging.DEBUG)        # restored by a LATER step
        logging.getLogger("test.m1o.new")   # removed by a LATER step
        return n
    _watch(f)
    assert lg.level == logging.WARNING, "a failing restore step skipped the named-logger restore"
    assert "test.m1o.new" not in logging.root.manager.loggerDict, "a failing restore step left a new logger registered"


def test_L_same_qualname_class_with_other_emit():
    # closed by the method-code fingerprint (was a strict xfail named limit at bc0d72ad)
    Same = type("_StderrHandler", (logging.Handler,), {"emit": lambda self, r: None, "__module__": "logging",
                                                       "stream": property(lambda self: sys.stderr)})

    def f(n):
        logging.lastResort = Same(ORIG.level)
        return n
    assert _watch(f) != _watch(_untouched)
