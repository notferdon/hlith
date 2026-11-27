"""review red-test list for a recorded review. Predeclared expectations are in the docstrings.

Each test asserts the DESIRED property: two different exit behaviours must not compare equal (or must be reported
untracked / unmeasurable), and the same behaviour must stay equal. In-process _StateWatch, no sandbox needed.
"""
import atexit
import importlib.util
import os
import sys
import types
import weakref
from pathlib import Path

import pytest

from hlith import differential
from hlith.differential import _StateWatch


@pytest.fixture
def _restore_atexit():
    reg, unreg = atexit.register, atexit.unregister
    yield
    atexit.register, atexit.unregister = reg, unreg


def _change(do, tree_root=None):
    mod = types.ModuleType("case_mod")
    mod.foo = lambda: 1
    w = _StateWatch(mod, mod.foo, tree_root=tree_root)
    do()
    return w.changes_and_restore(dict(os.environ))


def _cb(x=None):
    return x


# --- long arguments (PREDICT: pass, this is maintainer's repair) ---
def test_240_args_differ(_restore_atexit):
    a = _change(lambda: atexit.register(_cb, "x" * 240 + "a"))
    b = _change(lambda: atexit.register(_cb, "x" * 240 + "b"))
    assert a != b


def test_240_kwargs_differ(_restore_atexit):
    a = _change(lambda: atexit.register(_cb, x="x" * 240 + "a"))
    b = _change(lambda: atexit.register(_cb, x="x" * 240 + "b"))
    assert a != b


def test_240_closure_cell_differs(_restore_atexit):
    def mk(v):
        def inner():
            return v
        return inner
    a = _change(lambda: atexit.register(mk("x" * 240 + "a")))
    b = _change(lambda: atexit.register(mk("x" * 240 + "b")))
    assert a != b


def test_240_bound_method_self_differs(_restore_atexit):
    class K:
        def __init__(self, v):
            self.v = v

        def __repr__(self):
            return "K(" + self.v + ")"

        def run(self):
            return self.v
    a = _change(lambda: atexit.register(K("x" * 240 + "a").run))
    b = _change(lambda: atexit.register(K("x" * 240 + "b").run))
    # an arbitrary receiver object is OPAQUE (named limit): fail closed as unmeasurable, never repr equality
    assert a != b or "atexit identity untracked: unmeasurable" in a
    assert "atexit identity untracked: unmeasurable" in a and "atexit identity untracked: unmeasurable" in b


# --- identical short repr, different state (PREDICT: FAIL, repr-only identity) ---
def test_identical_short_repr_different_attribute_is_not_equal(_restore_atexit):
    class Opaque:
        def __init__(self, path):
            self.path = path

        def __repr__(self):
            return "<Opaque>"

    a = _change(lambda: atexit.register(_cb, Opaque("/work/a")))
    b = _change(lambda: atexit.register(_cb, Opaque("/work/b")))
    assert a != b or "untracked" in a or "unmeasurable" in a


# --- helper-callee body change (PREDICT: FAIL, co_names only) ---
def test_callee_body_change_is_not_equal(tmp_path, _restore_atexit):
    def load(side, body):
        p = tmp_path / side / "cbmod.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"def helper():\n    return {body!r}\n\n\ndef cb():\n    return helper()\n")
        spec = importlib.util.spec_from_file_location(f"cbmod_{side}", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m, str(tmp_path / side)
    ma, ra = load("base", "delete-a")
    mb, rb = load("post", "delete-b")
    a = _change(lambda: atexit.register(ma.cb), tree_root=ra)
    b = _change(lambda: atexit.register(mb.cb), tree_root=rb)
    assert a != b or "untracked" in a or "unmeasurable" in a


# --- weakref.finalize with two different callbacks (PREDICT: FAIL, single _exitfunc registration) ---
def test_weakref_finalize_callbacks_differ(_restore_atexit):
    class T:
        pass

    def fa():
        return "a"

    def fb():
        return "b"
    # first use registers weakref's own _exitfunc once; make that happen before the watch so only the finalizer is new
    keep = []
    t0 = T()
    keep.append(weakref.finalize(t0, _cb))
    ta, tb = T(), T()
    a = _change(lambda: keep.append(weakref.finalize(ta, fa)))
    b = _change(lambda: keep.append(weakref.finalize(tb, fb)))
    assert a != b or "untracked" in a or "unmeasurable" in a


# --- hostile __repr__ at register time (PREDICT: pass = no crash, never agreement on BaseException) ---
def test_hostile_repr_does_not_crash_or_agree(_restore_atexit):
    class Hostile:
        def __repr__(self):
            raise KeyboardInterrupt("hostile repr")

    try:
        a = _change(lambda: atexit.register(_cb, Hostile()))
    except KeyboardInterrupt:
        pytest.fail("a hostile __repr__ at register time escaped the watch as a BaseException")
    assert "atexit" in a


# --- relative tree_root + different cwd (PREDICT: pass if normalised at construction) ---
def test_relative_tree_root_and_different_cwd_same_callback_equal(tmp_path, _restore_atexit):
    def load(side):
        p = tmp_path / side / "pkg" / "m.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("def cb():\n    return 'same'\n")
        spec = importlib.util.spec_from_file_location(f"relmod_{side}", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    ma, mb = load("base"), load("post")
    old = os.getcwd()
    try:
        os.chdir(tmp_path)
        wa = _StateWatch(types.ModuleType("a"), lambda: 1, tree_root="base")
        atexit.register(ma.cb)
        os.chdir("/")  # the target changed directory after the watch was built
        a = wa.changes_and_restore(dict(os.environ))
        os.chdir(tmp_path)
        wb = _StateWatch(types.ModuleType("b"), lambda: 1, tree_root="post")
        atexit.register(mb.cb)
        os.chdir("/")
        b = wb.changes_and_restore(dict(os.environ))
    finally:
        os.chdir(old)
    assert a == b, (a, b)


# --- NEGATIVE control (item 3): the same callback with the same args must stay equal ---
def test_same_callback_same_args_stays_equal(_restore_atexit):
    a = _change(lambda: atexit.register(_cb, "x" * 240 + "a", ))
    b = _change(lambda: atexit.register(_cb, "x" * 240 + "a"))
    assert a == b, (a, b)
    c = _change(lambda: atexit.register(_cb, 1, 2))
    d = _change(lambda: atexit.register(_cb, 1, 2))
    assert c == d


# ---- added with the fix (D1-D4 regression and negative controls) ----
def test_opaque_value_is_never_agreement_and_repr_is_never_called(_restore_atexit):
    calls = []

    class Opaque:
        def __repr__(self):
            calls.append("repr")
            return "<Opaque>"

    a = _change(lambda: atexit.register(_cb, Opaque()))
    assert "atexit identity untracked: unmeasurable" in a
    assert not differential._agreement_counts({"g": a}, {"g": a})
    assert calls == [], "the watch must not run a target __repr__"


def test_net_zero_count_with_an_unmeasurable_callback_is_still_reported(_restore_atexit):
    class Opaque:
        pass

    def reg_unreg():
        obj = Opaque()
        atexit.register(_cb, obj)
        atexit.unregister(_cb)
    assert "unmeasurable" in _change(reg_unreg)


def test_module_constant_read_by_the_callback_is_part_of_its_identity(tmp_path, _restore_atexit):
    def load(side, path):
        p = tmp_path / side / "constmod.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"TARGET = {path!r}\n\n\ndef cb():\n    return TARGET\n")
        spec = importlib.util.spec_from_file_location(f"constmod_{side}", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    ma, mb = load("base", "/work/a"), load("post", "/work/b")
    a = _change(lambda: atexit.register(ma.cb), tree_root=str(tmp_path / "base"))
    b = _change(lambda: atexit.register(mb.cb), tree_root=str(tmp_path / "post"))
    assert a != b


def test_same_callee_in_two_trees_stays_equal(tmp_path, _restore_atexit):
    def load(side):
        p = tmp_path / side / "cbmod2.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("def helper():\n    return 'x'\n\n\ndef cb():\n    return helper()\n")
        spec = importlib.util.spec_from_file_location(f"cbmod2_{side}", p)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    ma, mb = load("base"), load("post")
    a = _change(lambda: atexit.register(ma.cb), tree_root=str(tmp_path / "base"))
    b = _change(lambda: atexit.register(mb.cb), tree_root=str(tmp_path / "post"))
    assert a == b, (a, b)


def test_same_weakref_finalizer_stays_equal(_restore_atexit):
    class T:
        pass

    def fa():
        return "a"
    keep = [weakref.finalize(T(), _cb)]
    ta, tb = T(), T()
    a = _change(lambda: keep.append(weakref.finalize(ta, fa)))
    b = _change(lambda: keep.append(weakref.finalize(tb, fa)))
    assert a == b and "weakref.finalize identity" in a


def test_hostile_identity_never_escapes_as_a_baseexception(_restore_atexit):
    class Opaque:
        def __getattr__(self, name):
            raise SystemExit("hostile attribute access")

    got = _change(lambda: atexit.register(_cb, Opaque()))
    assert "untracked" in got


# ---- review AT1 static predictions on c6fc68b5 (F1 defaults, F2 closure of a referenced function, F3 object protocol) ----
def _ns(src):
    ns = {"__name__": "case_ns"}
    exec(compile(src, "<case_ns>", "exec"), ns)
    return ns


def test_function_defaults_are_part_of_the_callback_identity(_restore_atexit):
    def mk(d):
        def cb(x=d):
            return x
        return cb
    a = _change(lambda: atexit.register(mk(1)))
    b = _change(lambda: atexit.register(mk(2)))
    assert a != b
    c = _change(lambda: atexit.register(mk(1)))
    assert a == c


def test_kwdefaults_are_part_of_the_callback_identity(_restore_atexit):
    def mk(d):
        def cb(*, x=d):
            return x
        return cb
    assert _change(lambda: atexit.register(mk(1))) != _change(lambda: atexit.register(mk(2)))


def test_defaults_of_a_referenced_function_are_part_of_the_identity(_restore_atexit):
    src = "def helper(x=%d):\n    return x\n\n\ndef cb():\n    return helper()\n"
    a = _change(lambda: atexit.register(_ns(src % 1)["cb"]))
    b = _change(lambda: atexit.register(_ns(src % 2)["cb"]))
    assert a != b


def test_closure_of_a_referenced_function_is_part_of_the_identity(_restore_atexit):
    src = "def mk(v):\n    def h():\n        return v\n    return h\n\n\nh = mk(%d)\n\n\ndef cb():\n    return h()\n"
    a = _change(lambda: atexit.register(_ns(src % 1)["cb"]))
    b = _change(lambda: atexit.register(_ns(src % 2)["cb"]))
    assert a != b
    assert a == _change(lambda: atexit.register(_ns(src % 1)["cb"]))


def test_callable_instance_with_getattr_supplying_code_is_unmeasurable_and_never_probed(_restore_atexit):
    probed = []
    real = (lambda: 1).__code__

    class Fake:
        def __getattr__(self, name):
            probed.append(name)
            if name == "__code__":
                return real
            raise AttributeError(name)

        def __call__(self):
            return "side effect at exit"

    got = _change(lambda: atexit.register(Fake()))
    assert "atexit identity untracked: unmeasurable" in got
    assert probed == [], probed


def test_a_class_property_claiming_functiontype_is_not_a_function(_restore_atexit):
    import types as _types

    class Spoof:
        @property
        def __class__(self):
            return _types.FunctionType

        def __call__(self):
            return 1

    ns = _ns("def cb():\n    return h()\n")
    ns["h"] = Spoof()
    got = _change(lambda: atexit.register(ns["cb"]))
    assert "atexit identity untracked: unmeasurable" in got


# ---- review AT2 F5/F6 (+ later-call mutation) and the toq 'm' agreement inconsistency ----
def test_function_dict_attribute_is_part_of_the_callback_identity(_restore_atexit):
    def mk(mode):
        def cb():
            return cb.mode
        cb.mode = mode
        return cb
    assert _change(lambda: atexit.register(mk("a"))) != _change(lambda: atexit.register(mk("b")))
    assert _change(lambda: atexit.register(mk("a"))) == _change(lambda: atexit.register(mk("a")))


def test_closure_mutated_later_in_the_same_call_is_seen(_restore_atexit):
    def run(final):
        box = []

        def cb():
            return list(box)

        def do():
            atexit.register(cb)
            box.append(final)  # mutated AFTER registration, inside the same call
        return _change(do)
    assert run("keep") != run("delete")
    assert run("keep") == run("keep")


def test_state_mutated_by_a_later_call_is_seen(_restore_atexit):
    box = []

    def cb():
        return list(box)

    mod = types.ModuleType("case_later")
    mod.foo = lambda: 1
    w = _StateWatch(mod, mod.foo)
    atexit.register(cb)
    first = w.changes_and_restore(dict(os.environ))
    box.append("delete-everything")  # a later call changes what the earlier registration will do at exit
    second = w.changes_and_restore(dict(os.environ))
    assert "identity changed after registration" in second, (first, second)
    box.clear()
    box.append("keep")
    third = w.changes_and_restore(dict(os.environ))
    assert "identity changed after registration" in third


def test_setup_error_over_cap_message_is_never_agreement():
    big = {"k": "exc", "t": "import:x.Y", "m": differential._cap_desc("z" * (differential._DESC_CAP + 5))}
    assert not differential._agreement_counts(big, big)
    ok = {"k": "exc", "t": "import:x.Y", "m": differential._cap_desc("short")}
    assert differential._agreement_counts(ok, ok)


# ---- review AT3 BIGMANY: the F6 re-identification must be bounded (it was O(calls^2): 25 s for 200 calls with a 2000-element arg) ----
def _many_calls(n_calls, arg_for):
    import time
    mod = types.ModuleType("case_many")
    mod.foo = lambda: 1
    w = _StateWatch(mod, mod.foo)
    t0 = time.time()
    last = ""
    for i in range(n_calls):
        atexit.register(_cb, arg_for(i))
        last = w.changes_and_restore(dict(os.environ))
    return time.time() - t0, last, w


def test_repeated_identical_registration_is_deduplicated_and_fast(_restore_atexit):
    big = tuple(range(2000))
    elapsed, last, w = _many_calls(120, lambda i: big)
    assert elapsed < 8.0, elapsed
    assert len(w._atexit_old) <= 2, len(w._atexit_old)
    assert "unmeasurable" not in last, last


def test_distinct_big_registrations_hit_the_budget_and_fail_closed(_restore_atexit, monkeypatch):
    monkeypatch.setattr(differential, "_ATEXIT_REID_BUDGET_NODES", 200_000)
    elapsed, last, w = _many_calls(120, lambda i: tuple(range(2000)) + (i,))
    assert elapsed < 20.0, elapsed
    assert "atexit identity untracked: unmeasurable" in last and "budget" in last, last


def test_the_reidentification_budget_is_deterministic_not_wall_clock(_restore_atexit, monkeypatch):
    """Two runs with the same inputs must trip (or not trip) at the same registration, whatever the machine load."""
    monkeypatch.setattr(differential, "_ATEXIT_REID_BUDGET_NODES", 200_000)
    seen = []
    for _ in range(2):
        _t, last, w = _many_calls(60, lambda i: tuple(range(2000)) + (i,))
        seen.append((w._atexit_reid_n, "budget" in last))
    assert seen[0] == seen[1], seen


# ---- guard note R-55be08bc P2: one callback must not exceed a per-identity node bound ----
def test_a_callback_referencing_many_large_globals_is_unmeasurable_not_unbounded(_restore_atexit):
    ns = {"__name__": "case_big"}
    names = [f"G{i}" for i in range(120)]
    src = "".join(f"{n} = list(range(4900))\n" for n in names) + "def cb():\n    return (" + ",".join(names) + ",)\n"
    exec(compile(src, "<case_big>", "exec"), ns)
    before = differential._ATX_WORK[0]
    got = _change(lambda: atexit.register(ns["cb"]))
    assert "atexit identity untracked: unmeasurable" in got and "too large" in got, got
    assert differential._ATX_WORK[0] - before < 3 * differential._ATEXIT_IDENT_NODES, "work must stop near the bound"


def test_a_modest_callback_is_still_measurable(_restore_atexit):
    ns = {"__name__": "case_small"}
    exec(compile("G = list(range(4000))\n\n\ndef cb():\n    return G\n", "<case_small>", "exec"), ns)
    got = _change(lambda: atexit.register(ns["cb"]))
    assert "unmeasurable" not in got and "atexit identity:" in got, got
