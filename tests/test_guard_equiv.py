# SPDX-License-Identifier: Apache-2.0
"""A neutral structural rewrite of entry guards is NOT a removed guard.

Ground truth is EXECUTION: both versions are run over a grid and must agree on every input (value or exception type
and message) for a rewrite to count as neutral; negatives must provably differ on some grid input. The decision under
test is guard_removed.removed_entry_guards (empty = no guard removed or changed).
"""
import itertools

import pytest

from hlith.guard_removed import removed_entry_guards

GRID = list(itertools.product(range(-6, 7), range(-6, 7)))


def _outcomes(src):
    g = {}
    exec(compile(src, "<fx>", "exec"), g)
    f = g["f"]
    out = {}
    for x, y in GRID:
        try:
            out[(x, y)] = ("ret", f(x, y))
        except Exception as e:  # noqa: BLE001
            out[(x, y)] = ("exc", type(e).__name__, str(e))
    return out


def _fn(body, sig="x: int, y: int"):
    return f"def f({sig}):\n" + "".join("    " + ln + "\n" for ln in body.strip("\n").splitlines())


NEUTRAL = {
    "reorder_two_guards": (
        "if x < 0:\n    raise ValueError('bad')\nif y < 0:\n    raise ValueError('bad')\nreturn x + y",
        "if y < 0:\n    raise ValueError('bad')\nif x < 0:\n    raise ValueError('bad')\nreturn x + y"),
    "merge_guards": (
        "if x < 0:\n    raise ValueError('bad')\nif y < 0:\n    raise ValueError('bad')\nreturn x + y",
        "if x < 0 or y < 0:\n    raise ValueError('bad')\nreturn x + y"),
    "split_guard": (
        "if x < 0 or y < 0:\n    raise ValueError('bad')\nreturn x + y",
        "if x < 0:\n    raise ValueError('bad')\nif y < 0:\n    raise ValueError('bad')\nreturn x + y"),
    "de_morgan": (
        "if not (x > 0 and y > 0):\n    raise ValueError('bad')\nreturn x + y",
        "if x <= 0 or y <= 0:\n    raise ValueError('bad')\nreturn x + y"),
    "not_and_vs_not_or_not": (
        "if not (x >= 2 and y != 3):\n    raise ValueError('bad')\nreturn x * y",
        "if (not x >= 2) or (not y != 3):\n    raise ValueError('bad')\nreturn x * y"),
    "inverted_early_return": (
        "if x >= 0 and y >= 0:\n    return x + y\nelse:\n    raise ValueError('bad')",
        "if not (x >= 0 and y >= 0):\n    raise ValueError('bad')\nreturn x + y"),
    "local_alias_in_condition": (
        "if x * 2 < 3:\n    raise ValueError('bad')\nreturn x + y",
        "m = x * 2\nif m < 3:\n    raise ValueError('bad')\nreturn x + y"),
    "constant_folding": (
        "if x < 2 * 3:\n    raise ValueError('bad')\nreturn x + y",
        "if x < 6:\n    raise ValueError('bad')\nreturn x + y"),
}

NEGATIVE = {  # behaviour provably differs on the grid; every one must stay blocked
    "dropped_guard": (
        "if x < 0:\n    raise ValueError('bad')\nif y < 0:\n    raise ValueError('bad')\nreturn x + y",
        "if x < 0:\n    raise ValueError('bad')\nreturn x + y"),
    "widened_guard": (
        "if x < 0:\n    raise ValueError('bad')\nreturn x + y",
        "if x < 3:\n    raise ValueError('bad')\nreturn x + y"),
    "narrowed_guard": (
        "if x < 3:\n    raise ValueError('bad')\nreturn x + y",
        "if x < 0:\n    raise ValueError('bad')\nreturn x + y"),
    "changed_exception_type": (
        "if x < 0:\n    raise ValueError('bad')\nreturn x + y",
        "if x < 0:\n    raise TypeError('bad')\nreturn x + y"),
    "different_exceptions_reordered": (  # both true on part of the grid: the FIRST one decides which exception
        "if x < 0:\n    raise ValueError('a')\nif y < 0:\n    raise TypeError('a')\nreturn x + y",
        "if y < 0:\n    raise TypeError('a')\nif x < 0:\n    raise ValueError('a')\nreturn x + y"),
    "guard_moved_after_side_effect": (
        "if x < 0:\n    raise ValueError('bad')\nLOG.append(x)\nreturn x + y",
        "LOG.append(x)\nif x < 0:\n    raise ValueError('bad')\nreturn x + y"),
    "guard_deleted_entirely": (
        "if x == 3:\n    raise ValueError('bad')\nreturn x + y",
        "return x + y"),
    "dropped_guard_with_reassigned_local_after": (
        "z = x > 3\nif z:\n    raise ValueError('bad')\nz = False\nreturn x",
        "return x"),
    "dropped_guard_with_reassigned_local_between_same_exc": (
        "z = x > 3\nif z:\n    raise ValueError('bad')\nz = y < 0\nif z:\n    raise ValueError('bad')\nreturn x + y",
        "z = y < 0\nif z:\n    raise ValueError('bad')\nreturn x + y"),
    "dropped_guard_with_transitive_local_reassigned": (
        "a = x > 3\nb = a\na = False\nif b:\n    raise ValueError('bad')\nreturn x",
        "return x"),
}
PRELUDE = "LOG = []\n\n\n"


def _src(body):
    return PRELUDE + _fn(body)


@pytest.mark.parametrize("name", sorted(NEUTRAL))
def test_neutral_guard_rewrites_are_not_removed_guards(name):
    pre, post = (_src(b) for b in NEUTRAL[name])
    assert _outcomes(pre) == _outcomes(post), "fixture is not actually neutral"  # the oracle
    got = removed_entry_guards(pre, post, "f")
    assert got == [], (name, got)


@pytest.mark.parametrize("name", sorted(NEGATIVE))
def test_real_guard_changes_stay_blocked(name):
    pre, post = (_src(b) for b in NEGATIVE[name])
    assert _outcomes(pre) != _outcomes(post) or name == "guard_moved_after_side_effect", "fixture does not change behaviour"
    got = removed_entry_guards(pre, post, "f")
    assert got, f"{name}: a real change to the raise set was not reported"


def test_undecidable_guards_fall_back_to_syntactic_identity():
    pre = PRELUDE + "def f(x):\n    if helper(x):\n        raise ValueError('b')\n    return x\n"
    same = pre.replace("return x", "return x + 0")
    assert removed_entry_guards(pre, same, "f") == []  # identical guard text: unchanged
    rewritten = PRELUDE + "def f(x):\n    if (helper(x)):\n        raise ValueError('b')\n    return x\n"
    assert removed_entry_guards(pre, rewritten, "f") == []  # same AST (parentheses are not syntax)
    other = PRELUDE + "def f(x):\n    if not not helper(x):\n        raise ValueError('b')\n    return x\n"
    assert removed_entry_guards(pre, other, "f"), "an undecidable rewrite cannot be proved neutral: blocked"


def test_string_and_len_guards_and_methods_and_elif_chains():
    pre = "class C:\n    def f(self, s: str, n: int):\n        if len(s) > 3:\n            raise ValueError('a')\n        if s == '' or n < 0:\n            raise ValueError('a')\n        return n\n"
    post = ("class C:\n    def f(self, s: str, n: int):\n        if n < 0 or s == '' or len(s) > 3:\n"
            "            raise ValueError('a')\n        return n\n")
    assert removed_entry_guards(pre, post, "C.f") == []
    widened = post.replace("len(s) > 3", "len(s) > 5")
    assert removed_entry_guards(pre, widened, "C.f")
    elif_pre = "def f(x: int):\n    if x < 0:\n        raise ValueError('a')\n    elif x > 10:\n        raise ValueError('a')\n    return x\n"
    elif_post = "def f(x: int):\n    if x < 0 or x > 10:\n        raise ValueError('a')\n    return x\n"
    assert removed_entry_guards(elif_pre, elif_post, "f") == []
    assert removed_entry_guards(elif_pre, elif_post.replace("x > 10", "x > 11"), "f")


def test_added_guards_are_not_reported_as_removed():
    pre = "def f(x: int):\n    return x\n"
    post = "def f(x: int):\n    if x < 0:\n        raise ValueError('a')\n    return x\n"
    assert removed_entry_guards(pre, post, "f") == []


def test_unannotated_parameter_is_decided_by_usage():
    pre = "def f(x):\n    if x < 0:\n        raise ValueError('a')\n    return x\n"
    post = "def f(x):\n    if not (x >= 0):\n        raise ValueError('a')\n    return x\n"
    assert removed_entry_guards(pre, post, "f") == []


def test_sequential_local_rebindings_keep_point_in_time_guard_meaning():
    pre = _src("z = x < 0\nif z:\n    raise ValueError('bad')\nz = y < 0\nif z:\n    raise ValueError('bad')\nreturn x + y")
    post = _src("if x < 0 or y < 0:\n    raise ValueError('bad')\nreturn x + y")
    assert _outcomes(pre) == _outcomes(post)
    assert removed_entry_guards(pre, post, "f") == []

    pre_param = _src("y_orig = y\ny = x + 1\nif y > 3:\n    raise ValueError('bad')\nif y_orig < 0:\n    raise ValueError('bad')\nreturn x")
    post_param = _src("if x + 1 > 3 or y < 0:\n    raise ValueError('bad')\nreturn x")
    assert removed_entry_guards(pre_param, post_param, "f") == []
