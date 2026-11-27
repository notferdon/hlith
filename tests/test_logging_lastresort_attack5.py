"""case round 5 (review on review's 38d6c1ad; regression file, included here).

REGRESSION class R (same as attack4 R1/R2, reintroduced by 6396117e's fast path and NOT fixed by 38d6c1ad): restore_handler's fast path
returns early on `h.level == lvl ... and h.filters == filters`, i.e. the attacker-controlled __eq__ of an int subclass level / of filter
elements. differs() itself is correct; the fast path bypasses it.
  R3  a handler level replaced by an int subclass with a lying __eq__ is NOT written back even when restore runs (root restores it)

PRE-EXISTING (also at root 92f4194a; for case with P1-P4):
  P5  a handler level replaced by an int subclass with lying comparisons, nothing else changed: the fingerprint coerces int(level), so
      not seen and not restored; logging's `record.levelno >= level` then uses the subclass (a WARNING handler emits DEBUG records)
  P6  h.filters replaced by a TUPLE of the same filters: restore compares list(h.filters) element-wise, so the tuple stays and a later
      addFilter() raises (type leak into later calls)
"""
import io
import logging
import os
import types

import pytest

from hlith import differential


class _LyingInt(int):
    def __eq__(self, o):
        return True

    def __ne__(self, o):
        return False

    def __hash__(self):
        return 0

    def __le__(self, o):
        return True

    def __ge__(self, o):
        return True


def _watch(fn):
    mod = types.ModuleType("n2_m1o_a5")
    mod.f = fn
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    return w.changes_and_restore(dict(os.environ), restore=True)


def _untouched(n):
    return n


@pytest.fixture
def handler():
    h = logging.StreamHandler(io.StringIO())
    h.setLevel(logging.WARNING)
    f0 = logging.Filter("test")
    h.addFilter(f0)
    lg = logging.getLogger("test.a5")
    lg.addHandler(h)
    lg.setLevel(logging.DEBUG)
    lg.propagate = False
    yield h, f0, lg
    lg.removeHandler(h)


def test_R3_int_subclass_level_is_written_back_when_restore_runs(handler):
    h, _f0, _lg = handler
    other = logging.getLogger("test.a5.other")

    def f(n):
        h.level = _LyingInt(logging.WARNING)
        other.setLevel(logging.ERROR if other.level != logging.ERROR else logging.INFO)  # a detected change: restore runs
        return n
    _watch(f)
    assert type(h.level) is int and h.level == logging.WARNING, "restore's fast path trusted the int subclass's lying __eq__"


def test_P5_lying_level_alone_is_seen_or_restored(handler):
    h, _f0, lg = handler
    out = _watch(lambda n: (setattr(h, "level", _LyingInt(logging.WARNING)), n)[1])
    assert out != _watch(_untouched) or type(h.level) is int, "a level with lying comparisons was neither seen nor restored"


def test_P6_filters_tuple_is_restored_to_the_list(handler):
    h, f0, _lg = handler
    other = logging.getLogger("test.a5.other6")

    def f(n):
        h.filters = (f0,)
        other.setLevel(logging.ERROR if other.level != logging.ERROR else logging.INFO)
        return n
    _watch(f)
    assert type(h.filters) is list and h.filters == [f0], "h.filters left as a tuple: a later addFilter() raises"


def test_P7_stdlib_class_method_replaced_plainly_is_restored():
    """An ordinary class-level replacement must be both reported and restored."""
    orig = logging.StreamHandler.emit

    def f(n):
        def dropped_emit(self, record):
            return None
        logging.StreamHandler.emit = dropped_emit
        return n

    try:
        out = _watch(f)
        seen = out != _watch(_untouched) if logging.StreamHandler.emit is orig else ("emit" in out or "logging" in out)
        assert logging.StreamHandler.emit is orig, f"seen={seen}: StreamHandler.emit stayed installed for later calls"
    finally:
        logging.StreamHandler.emit = orig
