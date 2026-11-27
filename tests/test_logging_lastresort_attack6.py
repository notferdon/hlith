"""case round 6 (review on review's 29c30f85; regression file, included here).

REGRESSION introduced by 6396117e's per-pass class-fingerprint memo (2b1e0037, which had no memo, distinguishes this):
  R4  `cls in memo` hashes/compares the CLASS, so a handler class whose metaclass impersonates logging.StreamHandler (__hash__ +
      __eq__) receives StreamHandler's method fingerprint from the memo: a handler that silently DROPS every record produces the same
      change string as a plain StreamHandler (base adds a plain one, the patch adds the dropping one: the sides agree -> false HELD).
      Fix: key the memo by id(cls) and accept a hit only if the stored class `is` cls (as the weak cache already re-validates).
WEAK (detection only, restored by identity):
  W1  a stream swapped for one whose .name is a str subclass with a lying __eq__ is not reported (the fingerprint's dest compares by ==)
"""
import io
import logging
import os
import types

import pytest

from hlith import differential


def _watch(fn):
    mod = types.ModuleType("n2_m1o_a6")
    mod.f = fn
    w = differential._StateWatch(mod, fn, None, None)
    fn(2)
    return w.changes_and_restore(dict(os.environ), restore=True)


class _Meta(type):
    def __eq__(cls, o):
        return True

    def __hash__(cls):
        return hash(logging.StreamHandler)


_Dropping = _Meta("StreamHandler", (logging.StreamHandler,), {"emit": lambda self, record: None, "__module__": "logging"})


def test_R4_metaclass_impersonation_does_not_borrow_a_class_fingerprint():
    real = logging.StreamHandler(io.StringIO())
    a, b = logging.getLogger("test.a6.a"), logging.getLogger("test.a6.b")
    a.addHandler(real)  # a real StreamHandler is fingerprinted first in each pass
    try:
        def add_dropping(n):
            b.addHandler(_Dropping(io.StringIO()))
            return n

        def add_plain(n):
            b.addHandler(logging.StreamHandler(io.StringIO()))
            return n
        dropping, plain = _watch(add_dropping), _watch(add_plain)
        assert dropping != plain, "a record-dropping handler compared equal to a plain StreamHandler (memo lookup by class hash/eq)"
    finally:
        a.removeHandler(real)
        for x in list(b.handlers):
            b.removeHandler(x)


class _LyingName(str):
    def __eq__(self, other):
        return True

    def __hash__(self):
        return 0


def test_W1_stream_name_subclass_is_fingerprinted_without_equality():
    h = logging.StreamHandler(io.StringIO())
    original = h.stream
    try:
        before = differential._logging_handler_fp(h)
        h.stream = type("Stream", (), {"name": _LyingName("attacker")})()
        after = differential._logging_handler_fp(h)
        assert before != after, "different stream name objects with lying equality compared as the same destination"
    finally:
        h.stream = original


def test_handler_class_swap_is_seen_and_restored():
    h = logging.StreamHandler(io.StringIO())
    lg = logging.getLogger("test.a6.class-swap")
    lg.addHandler(h)
    cls = type(h)

    class Evil(logging.StreamHandler):
        pass

    try:
        out = _watch(lambda n: (setattr(h, "__class__", Evil), n)[1])
        assert out, "same-instance handler class swap was not measured"
        assert type(h) is cls, "same-instance handler class swap was not restored"
    finally:
        lg.removeHandler(h)


def test_1000_handlers_scan_each_concrete_class_mro_once(monkeypatch):
    lg = logging.getLogger("test.a6.cost")
    handlers = [logging.StreamHandler(io.StringIO()) for _ in range(1000)]
    for handler in handlers:
        lg.addHandler(handler)
    scans = []
    original = differential._logging_class_mro_fp

    def counted(cls, names=differential._LG_METHOD_NAMES, memo=None):
        cache = {} if memo is None else memo.get("_mro", {})
        hit = cache.get(id(cls))
        if hit is None or hit[0] is not cls or names not in hit[1]:
            scans.append(id(cls))
        return original(cls, names, memo)

    monkeypatch.setattr(differential, "_logging_class_mro_fp", counted)
    try:
        differential._logging_cmp()
        assert len(scans) <= 8, f"1000 attached handlers caused {len(scans)} MRO scans"
    finally:
        for handler in handlers:
            lg.removeHandler(handler)


class _CallableLiar(type):
    def __eq__(cls, other):
        return True

    def __hash__(cls):
        return 1


def test_R6_callable_type_classification_does_not_use_metaclass_equality():
    h = logging.StreamHandler(io.StringIO())
    fmt = logging.Formatter("%(message)s")
    h.setFormatter(fmt)
    lg = logging.getLogger("test.a6.r6")
    lg.addHandler(h)
    fake_type = _CallableLiar("localtime", (), {
        "__call__": lambda self, t=None: __import__("time").gmtime(0),
        "__module__": "time",
    })
    fake = fake_type()
    fake.__module__, fake.__qualname__ = "time", "localtime"
    try:
        out = _watch(lambda n: (setattr(fmt, "converter", fake), n)[1])
        assert out or "converter" not in vars(fmt),\
            "a callable instance with a lying metaclass impersonated the stdlib Formatter.converter"
        assert "converter" not in vars(fmt), "instance converter override was not restored"
    finally:
        lg.removeHandler(h)
