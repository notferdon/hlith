"""review LG1 (attackassembly 37d6f1ac, hlith/review-final-both 8ec80e00): four FALSE HELD in the logging fingerprint, each target ONLY configuring logger
'app': stream (stdout -> stderr), Formatter fmt differing after char 120, datefmt, a handler filter's code; plus logger.filters (L2).
_logging_handler_fp compared (type, level, _fmt[:120], filter (type, name)). Each shape must change the change string (or be marked
unmeasurable through the untracked channel); an identical configuration must stay equal and unflagged."""
import contextlib
import io
import logging
import os
import sys
import types

import pytest

from hlith import differential

NAME = "app.n1lg1"


def _watch(fn):
    mod = types.ModuleType("n1_lg_probe")
    mod.f = fn
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    return w.changes_and_restore(dict(os.environ), restore=True)


def _differs(a: str, b: str) -> bool:
    return a != b or "atexit identity untracked" in a


def test_formatter_fmt_differing_after_char_120_is_seen():
    def mk(tag):
        def f(n):
            h = logging.StreamHandler(io.StringIO())
            h.setFormatter(logging.Formatter("%(message)s" + "x" * 130 + tag))
            logging.getLogger(NAME).addHandler(h)
            return n
        return f
    assert _differs(_watch(mk("a")), _watch(mk("b")))


def test_formatter_datefmt_is_seen():
    def mk(df):
        def f(n):
            h = logging.NullHandler()
            h.setFormatter(logging.Formatter("%(message)s", df))
            logging.getLogger(NAME).addHandler(h)
            return n
        return f
    assert _differs(_watch(mk("%H")), _watch(mk("%M")))


def test_handler_filter_code_is_seen():
    def mk(val):
        def f(n):
            h = logging.NullHandler()
            h.addFilter(lambda r: val)
            logging.getLogger(NAME).addHandler(h)
            return n
        return f
    assert _differs(_watch(mk(False)), _watch(mk(True)))


def test_logger_filter_code_is_seen():
    def mk(val):
        def f(n):
            logging.getLogger(NAME).addFilter(lambda r: val)
            return n
        return f
    assert _differs(_watch(mk(False)), _watch(mk(True)))


def test_stream_stdout_vs_stderr_under_redirection_is_unmeasurable_not_equal():
    def mk(which):
        def f(n):
            logging.getLogger(NAME).addHandler(logging.StreamHandler(getattr(sys, which)))
            return n
        return f

    def run(which):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return _watch(mk(which))
    a, b = run("stdout"), run("stderr")
    assert "atexit identity untracked: unmeasurable" in a and "atexit identity untracked: unmeasurable" in b, (a, b)


def test_identical_configuration_stays_equal_and_unflagged():
    def f(n):
        h = logging.NullHandler()
        h.setFormatter(logging.Formatter("%(message)s", "%H"))
        h.addFilter(lambda r: True)
        logging.getLogger(NAME).addHandler(h)
        return n
    a, b = _watch(f), _watch(f)
    assert a == b and a and "untracked" not in a, (a, b)


# ---- review LG3 (attackassembly f3c2b945, hlith/review-imh 4ad561da): formatter defaults / converter, and process-wide logging settings ----
def test_formatter_defaults_are_seen():
    def mk(v):
        def f(n):
            h = logging.NullHandler()
            h.setFormatter(logging.Formatter("%(message)s %(tag)s", defaults={"tag": v}))
            logging.getLogger(NAME).addHandler(h)
            return n
        return f
    assert _differs(_watch(mk("a")), _watch(mk("b")))


def test_formatter_converter_is_seen():
    import time

    def mk(conv):
        def f(n):
            h = logging.NullHandler()
            fm = logging.Formatter("%(message)s")
            fm.converter = conv
            h.setFormatter(fm)
            logging.getLogger(NAME).addHandler(h)
            return n
        return f
    assert _differs(_watch(mk(time.gmtime)), _watch(mk(time.localtime)))


@pytest.mark.xfail(strict=True, reason="NAMED LIMIT: process-wide logging settings are NOT fingerprinted: logging.setLogRecordFactory, "
                   "logging.raiseExceptions, logging.setLoggerClass (the LGfactory case landed HELD). Out of the case claim; a fix flips this to XPASS.")
def test_log_record_factory_change_is_seen():
    orig = logging.getLogRecordFactory()

    def mk(tag):
        def f(n):
            old = logging.getLogRecordFactory()
            logging.setLogRecordFactory(lambda *a, **k: (tag, old(*a, **k))[1])
            return n
        return f
    try:
        assert _differs(_watch(mk("a")), _watch(mk("b")))
    finally:
        logging.setLogRecordFactory(orig)


def test_formatter_defaults_stay_measurable_after_a_lot_of_prior_identity_work():
    """review LG3 static note: the defaults path called _atexit_val without resetting the per-identity work counter, so after >200k units of earlier
    work in the process every Formatter(defaults=...) became '<opaque ...>' (an over-refusal that grows with process age)."""
    differential._ATX_WORK[0] += 10_000_000  # simulate a long-lived evaluator process
    h = logging.NullHandler()
    h.setFormatter(logging.Formatter("%(message)s %(tag)s", defaults={"tag": "a"}))
    fp = differential._logging_handler_fp(h)
    assert "<opaque" not in repr(fp), fp
