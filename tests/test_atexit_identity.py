# SPDX-License-Identifier: Apache-2.0
"""Equal atexit counts are not the same callback (issue #4, not review F3).

review F3 already refutes a register where the base registers nothing: the COUNT changes.
The hole is the other way. ``register(cb_a)`` and ``register(cb_b)`` both add one callback,
so the change strings used to compare equal, a preservation check could be HELD, and a
returns-delta cannot excuse a ``g`` difference that was never reported.

What this file actually runs here:
  * the watch, in-process. Same callback in two trees compares equal (the tree root is not
    behaviour). Different callbacks do not, while the numeric ``+1 this call`` line still matches.
  * ``lambda: "a"`` and ``lambda: "b"`` share ``co_code``; the constant is part of the identity.
  * a register captured before the watch is ``atexit identity untracked`` and is not agreement.
  * a returns delta does not cover an identity difference.

The confined ``run_differential`` is skipped where landlock_create_ruleset is ENOSYS. That skip
is not a pass and not an observation of HELD. On a Landlock host it expects REFUTED for the
cb_a/cb_b swap and not REFUTED for an equivalent return that registers the same callback.
"""
from __future__ import annotations

import ctypes
import importlib.util
import os
from pathlib import Path

import pytest

from hlith import differential
from hlith.types import Verdict

_SRC = '''\
def cb_a():
    return "a"


def cb_b():
    return "b"


def f_a(n):
    import atexit
    atexit.register(cb_a)
    return n * 2


def f_b(n):
    import atexit
    atexit.register(cb_b)
    return n * 2
'''

_REEXPORT = '''\
from atexit import register


def cb_a():
    return "a"


def f(n):
    register(cb_a)
    return n * 2
'''


def _landlock_absent() -> bool:
    """True only when the kernel does not implement landlock_create_ruleset (errno 38).

    A present implementation returns EINVAL for a null ruleset, not ENOSYS. Any other errno is
    treated as present so the confined test runs on a real Landlock host.
    """
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        n = libc.syscall(444, 0, 0, 0)
    except (OSError, AttributeError):
        return False
    return n < 0 and ctypes.get_errno() == 38


def _atexit_parts(text: str) -> str:
    return "; ".join(p.strip() for p in text.split(";") if "atexit" in p)


def _load(path: Path, modname: str):
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _watch_call(mod, fn, tree: Path) -> str:
    env = dict(os.environ)
    watch = differential._StateWatch(mod, fn, None, os.path.abspath(tree) + os.sep)
    fn(2)
    return watch.changes_and_restore(env, restore=True)


@pytest.fixture
def _restore_atexit():
    import atexit

    real_reg = getattr(atexit.register, "_hlith_real_register", atexit.register)
    real_unreg = getattr(atexit.unregister, "_hlith_real_unregister", atexit.unregister)
    try:
        yield real_unreg
    finally:
        atexit.register = real_reg
        atexit.unregister = real_unreg


def _write_tree(root: Path, src: str) -> Path:
    pkg = root / "pkg"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    path = pkg / "m.py"
    path.write_text(src)
    return path


def test_same_callback_in_two_trees_compares_equal(tmp_path, _restore_atexit):
    """Negative control: the tree directory is not part of the callback identity."""
    unreg = _restore_atexit
    paths = []
    mods = []
    for i, name in enumerate(("tree_a", "tree_b")):
        root = tmp_path / name
        path = _write_tree(root, _SRC)
        paths.append(root)
        mods.append(_load(path, f"hlith_ax_same_{i}"))
    left = _watch_call(mods[0], mods[0].f_a, paths[0])
    right = _watch_call(mods[1], mods[1].f_a, paths[1])
    unreg(mods[0].cb_a)
    unreg(mods[1].cb_a)
    assert _atexit_parts(left) == _atexit_parts(right), (left, right)
    assert "atexit identity:" in left and "cb_a" in left
    assert "<tree>/pkg/m.py:cb_a:" in left
    assert "atexit identity untracked" not in left
    assert "+1 this call" in left


def test_different_callbacks_same_count_do_not_compare_equal(tmp_path, _restore_atexit):
    """The numeric channel agrees (+1). The identity channel does not. That is the false-HELD hole."""
    unreg = _restore_atexit
    root = tmp_path / "tree"
    path = _write_tree(root, _SRC)
    mod = _load(path, "hlith_ax_diff")
    left = _watch_call(mod, mod.f_a, root)
    right = _watch_call(mod, mod.f_b, root)
    unreg(mod.cb_a)
    unreg(mod.cb_b)
    assert "+1 this call" in left and "+1 this call" in right
    assert _atexit_parts(left) != _atexit_parts(right), (left, right)
    assert "cb_a" in left and "cb_b" in right
    assert "atexit identity:" in left and "atexit identity:" in right
    # a declared return cannot launder a g difference (O3: a delta is an outcome, never a state write)
    delta = {"type": "expr", "param": "n", "expr": "n > 0",
             "expected": {"kind": "returns", "value_repr": "4"}}
    pre = {"k": "ret", "r": "4", "g": left, "w": "", "out": ""}
    post = {"k": "ret", "r": "4", "g": right, "w": "", "out": ""}
    assert differential._same(pre, post) is False
    assert differential._delta_covers(delta, [2], {}, ["n"], post, pre) is False


def test_lambda_constants_are_part_of_the_identity(tmp_path, _restore_atexit):
    """``co_code`` is identical for ``lambda: "a"`` and ``lambda: "b"``. The constant is the behaviour."""
    src = (
        "def f_a(n):\n"
        "    import atexit\n"
        "    atexit.register(lambda: 'a')\n"
        "    return n * 2\n"
        "\n"
        "def f_b(n):\n"
        "    import atexit\n"
        "    atexit.register(lambda: 'b')\n"
        "    return n * 2\n"
    )
    same = (
        "def f_a(n):\n"
        "    import atexit\n"
        "    atexit.register(lambda: 'a')\n"
        "    return n * 2\n"
    )
    root = tmp_path / "tree"
    mod = _load(_write_tree(root, src), "hlith_ax_lam")
    left = _watch_call(mod, mod.f_a, root)
    right = _watch_call(mod, mod.f_b, root)
    assert "+1 this call" in left and "+1 this call" in right
    assert _atexit_parts(left) != _atexit_parts(right), (left, right)
    mods = []
    roots = []
    for i, name in enumerate(("la", "lb")):
        r = tmp_path / name
        mods.append(_load(_write_tree(r, same), f"hlith_ax_lam_{i}"))
        roots.append(r)
    a = _watch_call(mods[0], mods[0].f_a, roots[0])
    b = _watch_call(mods[1], mods[1].f_a, roots[1])
    assert _atexit_parts(a) == _atexit_parts(b), (a, b)
    assert _restore_atexit is not None


def test_module_level_from_import_is_tracked(tmp_path, _restore_atexit):
    """``from atexit import register`` is rebound to the wrap. It must not look untracked."""
    unreg = _restore_atexit
    root = tmp_path / "tree"
    path = _write_tree(root, _REEXPORT)
    mod = _load(path, "hlith_ax_reexport")
    text = _watch_call(mod, mod.f, root)
    unreg(mod.cb_a)
    assert "atexit identity:" in text and "cb_a" in text, text
    assert "atexit identity untracked" not in text


def test_register_captured_before_the_watch_is_not_agreement(_restore_atexit):
    """A default argument holding the original register bypasses the wrap. Unknown is not agreement."""
    import atexit
    import types

    unreg = _restore_atexit
    real = getattr(atexit.register, "_hlith_real_register", atexit.register)

    def cb():
        return "a"

    def f(n, reg=real):
        reg(cb)
        return n

    mod = types.ModuleType("hlith_ax_captured")
    mod.f = f
    mod.cb = cb
    env = dict(os.environ)
    # tree_root=None: do not walk the checkout. A root of "." would rebind every repo module.
    watch = differential._StateWatch(mod, f, None, None)
    f(2)
    text = watch.changes_and_restore(env, restore=True)
    unreg(cb)
    assert "atexit callbacks registered changed: +1 this call" in text, text
    assert "atexit identity untracked: +1 registered, 0 recorded" in text, text
    pair = {"k": "ret", "r": "2", "g": text, "w": ""}
    assert differential._same(pair, pair) is True
    assert differential._agreement_counts(pair, pair) is False


_SKIP_NO_LANDLOCK = pytest.mark.skipif(
    _landlock_absent(),
    reason="Landlock syscall 444 returned ENOSYS (errno 38). The confined differential was not executed. "
           "This skip is not a pass and not an observation of HELD or REFUTED.",
)

_DIFF_BASE = '''\
def cb_a():
    return "a"


def cb_b():
    return "b"


def f(n: int) -> int:
    import atexit
    atexit.register(cb_a)
    if n > 10:
        return n + 1
    return n * 2
'''

_DIFF_TEST = "from pkg.m import f\n\n\ndef test_f():\n    assert f(2) == 4\n    assert f(12) == 13\n"


def _run_diff(tmp_path, post: str):
    for side, body in (("base", _DIFF_BASE), ("post", post)):
        root = tmp_path / side
        (root / "pkg").mkdir(parents=True)
        (root / "pkg" / "__init__.py").write_text("")
        (root / "pkg" / "m.py").write_text(body)
        (root / "tests").mkdir()
        (root / "tests" / "test_m.py").write_text(_DIFF_TEST)
    (tmp_path / "proposer").mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), adequacy_gate=True)


@_SKIP_NO_LANDLOCK
def test_confined_callback_swap_is_refuted(tmp_path):
    post = _DIFF_BASE.replace("atexit.register(cb_a)", "atexit.register(cb_b)")
    ob = _run_diff(tmp_path, post)
    assert ob.verdict is Verdict.REFUTED and "atexit identity" in (ob.witness or ""), (ob.verdict, ob.witness, ob.stop_reason)


@_SKIP_NO_LANDLOCK
def test_confined_same_callback_equivalent_return_is_not_refuted(tmp_path):
    post = _DIFF_BASE.replace("    return n * 2\n", "    return 2 * n\n")
    ob = _run_diff(tmp_path, post)
    assert ob.verdict is not Verdict.REFUTED, (ob.verdict, ob.witness, ob.stop_reason)


def test_long_callback_arguments_do_not_alias_a_different_exit_action(_restore_atexit):
    """Truncating the callback argument repr must not launder a different exit effect."""
    import atexit
    import types

    unreg = _restore_atexit

    def exit_callback(payload: str):
        return payload[-1]

    def f_a(n):
        atexit.register(exit_callback, "x" * 240 + "a")
        return n

    def f_b(n):
        atexit.register(exit_callback, "x" * 240 + "b")
        return n

    mod = types.ModuleType("hlith_ax_long_callback_args")
    mod.f_a = f_a
    mod.f_b = f_b
    mod.exit_callback = exit_callback
    outputs = []
    try:
        for fn in (f_a, f_b):
            env = dict(os.environ)
            watch = differential._StateWatch(mod, fn, None, None)
            value = fn(2)
            g = watch.changes_and_restore(env, restore=True)
            outputs.append({"k": "ret", "r": str(value), "g": g, "w": "", "out": ""})
    finally:
        unreg(exit_callback)
    assert "+1 this call" in outputs[0]["g"] and "+1 this call" in outputs[1]["g"]
    assert "atexit identity:" in outputs[0]["g"] and "atexit identity:" in outputs[1]["g"]
    assert not differential._same(*outputs), "truncated callback arguments are a false agreement"
