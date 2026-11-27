"""case: StateWatch change descriptors compared repr[:200], so two values identical in their first 200 characters
and different after produced EQUAL change strings (false HELD; same class as case).
The display may be truncated; the comparison must use a digest of the whole bounded value, and a value over the cap is
unmeasurable (never agreement)."""
import os
import types

import pytest

from hlith import differential
from hlith.differential import _StateWatch

PREFIX = "x" * 250


def _changes(setup, mutate):
    mod = types.ModuleType("long_mod")
    fn, cls = setup(mod)
    mod.foo = fn
    w = _StateWatch(mod, fn, cls=cls)
    mutate(mod, fn, cls)
    return w.changes_and_restore(dict(os.environ))


def _pair(setup, mutate_for):
    return _changes(setup, mutate_for("a")), _changes(setup, mutate_for("b"))


def _plain(mod):
    def fn(a=""):
        return a
    mod.G = ""
    return fn, None


def test_module_global_long_values_differ():
    a, b = _pair(_plain, lambda t: (lambda mod, fn, cls: setattr(mod, "G", PREFIX + t)))
    assert "G=" in a and a != b


def test_function_defaults_long_values_differ():
    a, b = _pair(_plain, lambda t: (lambda mod, fn, cls: setattr(fn, "__defaults__", (PREFIX + t,))))
    assert "__defaults__" in a and a != b


def test_function_dict_long_values_differ():
    a, b = _pair(_plain, lambda t: (lambda mod, fn, cls: setattr(fn, "mark", PREFIX + t)))
    assert "__dict__" in a and a != b


def test_closure_cell_long_values_differ():
    def setup(mod):
        def mk():
            v = ""

            def fn():
                return v
            return fn
        mod.G = ""
        return mk(), None
    a, b = _pair(setup, lambda t: (lambda mod, fn, cls: setattr(fn.__closure__[0], "cell_contents", PREFIX + t)))
    assert "closure cell" in a and a != b


def test_class_attribute_long_values_differ():
    def setup(mod):
        class K:
            C = ""
        mod.G = ""
        return (lambda: 1), K
    a, b = _pair(setup, lambda t: (lambda mod, fn, cls: setattr(cls, "C", PREFIX + t)))
    assert "K.C" in a and a != b


def test_identical_long_values_stay_equal():
    a, b = _pair(_plain, lambda t: (lambda mod, fn, cls: setattr(mod, "G", PREFIX + "same")))
    assert a == b and a


def test_display_is_truncated_but_names_the_length_and_digest():
    a = _changes(_plain, lambda mod, fn, cls: setattr(mod, "G", PREFIX + "tail"))
    assert len(a) < 600 and "sha256=" in a and "len=" in a


def test_value_over_the_cap_is_unmeasurable_never_agreement():
    big = "y" * (differential._DESC_CAP + 10)
    a = _changes(_plain, lambda mod, fn, cls: setattr(mod, "G", big))
    assert "unmeasurable over cap" in a
    assert not differential._agreement_counts({"g": a}, {"g": a})


def test_setup_error_messages_use_a_digest_not_a_prefix():
    m1 = differential._cap_desc("e" * 250 + "a")
    m2 = differential._cap_desc("e" * 250 + "b")
    assert m1 != m2 and m1.startswith("e" * 200)
    assert differential._cap_desc("short") == "short"

