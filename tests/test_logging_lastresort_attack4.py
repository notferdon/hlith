"""case round 4 (review attack on review's 6396117e; regression file, included here).

REGRESSION introduced by 6396117e (green on 2b1e0037): _logging_restore's differs() treats `cur == want` as "already restored", so a
replacement OBJECT with a lying __eq__ is never written back (round 2 restored it unconditionally):
  R1  lastResort replaced by a handler whose __eq__ returns True: SEEN, but NOT restored (leaks into every later call)
  R2  a handler's formatter replaced by a same-named subclass with a lying __eq__: neither seen nor restored (silent leak)
  Fix: compare OBJECT-valued slots (lastResort, formatter, stream, handler lists' elements) by identity; == only for scalars.

PRE-EXISTING gaps (also at root 92f4194a and 2b1e0037; for the owner/design review: fix or name as limits, not regressions):
  P1  a stdlib handler method replaced ON THE CLASS by a function that fakes __module__='logging' / __qualname__ (stdlib callables are
      fingerprinted by name; class attributes are not in the identity record): not seen, persists (records silently dropped)
  P2  in-place __code__ swap of a stdlib handler method: not seen, persists
  P3  a formatter replaced by a same-named subclass with another format() (formatter methods are not fingerprinted): not seen
  P4  a logger OBJECT replaced in loggerDict (child loggers keep the orphaned parent): not seen, not restored
"""
import io
import logging
import os
import types

import pytest

from hlith import differential

ORIG_LR = logging.lastResort


def _watch(fn):
    mod = types.ModuleType("n2_m1o_a4")
    mod.f = fn
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    return w.changes_and_restore(dict(os.environ), restore=True)


def _untouched(n):
    return n


@pytest.fixture(autouse=True)
def _reset():
    emit, code = logging.StreamHandler.emit, logging.StreamHandler.emit.__code__
    yield
    logging.lastResort = ORIG_LR
    logging.StreamHandler.emit = emit
    logging.StreamHandler.emit.__code__ = code


class _Liar(logging.Handler):
    def __eq__(self, o):
        return True

    def __hash__(self):
        return 0


def test_R1_lying_eq_last_resort_is_restored():
    def f(n):
        logging.lastResort = _Liar(ORIG_LR.level)
        return n
    assert _watch(f) != _watch(_untouched)
    assert logging.lastResort is ORIG_LR, "a lastResort with a lying __eq__ was seen but not written back"


def _same_named_formatter(lying):
    ns = {"format": lambda self, record: "", "__module__": "logging"}
    if lying:
        ns.update(__eq__=lambda self, o: True, __hash__=lambda self: 0)
    return type("Formatter", (logging.Formatter,), ns)


def test_R2_lying_eq_formatter_is_restored():
    h = logging.StreamHandler(io.StringIO())
    orig = logging.Formatter("%(message)s")
    h.setFormatter(orig)
    lg = logging.getLogger("test.a4.r2")
    lg.addHandler(h)
    try:
        F = _same_named_formatter(lying=True)

        def f(n):
            h.setFormatter(F("%(message)s"))
            return n
        _watch(f)
        assert h.formatter is orig, "a formatter with a lying __eq__ was not written back"
    finally:
        lg.removeHandler(h)


def test_P1_stdlib_method_replaced_on_class_with_faked_name():
    def f(n):
        def emit(self, record):
            return None
        emit.__module__, emit.__qualname__ = "logging", "StreamHandler.emit"
        logging.StreamHandler.emit = emit
        return n
    orig = logging.StreamHandler.emit
    out = _watch(f)
    assert out != _watch(_untouched) or logging.StreamHandler.emit is orig,\
        "StreamHandler.emit replaced on the class: neither seen nor restored"


def test_P2_stdlib_method_code_swap():
    code = logging.StreamHandler.emit.__code__

    def f(n):
        def dead(self, record):
            return None
        logging.StreamHandler.emit.__code__ = dead.__code__
        return n
    out = _watch(f)
    assert out != _watch(_untouched) or logging.StreamHandler.emit.__code__ is code, "emit.__code__ swapped: neither seen nor restored"


def test_P3_same_named_formatter_with_other_format_is_seen():
    h = logging.StreamHandler(io.StringIO())
    h.setFormatter(logging.Formatter("%(message)s"))
    lg = logging.getLogger("test.a4.p3")
    lg.addHandler(h)
    try:
        F = _same_named_formatter(lying=False)

        def f(n):
            h.setFormatter(F("%(message)s"))
            return n
        assert _watch(f) != _watch(_untouched), "a formatter whose format() differs compared equal"
    finally:
        lg.removeHandler(h)


def test_P4_logger_object_replacement_is_seen_or_restored():
    lg = logging.getLogger("test.a4.p4")
    logging.getLogger("test.a4.p4.child")

    def f(n):
        mgr = logging.root.manager
        old = mgr.loggerDict.pop("test.a4.p4")
        logging.getLogger("test.a4.p4").setLevel(old.level)
        return n
    out = _watch(f)
    assert out != _watch(_untouched) or logging.root.manager.loggerDict.get("test.a4.p4") is lg,\
        "the logger object was replaced (children keep the old parent): neither seen nor restored"
