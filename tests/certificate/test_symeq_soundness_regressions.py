# SPDX-License-Identifier: Apache-2.0
"""Soundness regressions for symbolic equivalence (symeq) and certificate normalization/domain enforcement.

Every negative test below witnesses a real CPython divergence and MUST be refused by both
`symeq.prove` and `equiv_cert.certify_sources` (or `certify` for tree-level cases).
"""

from __future__ import annotations

import pytest

from hlith.obligation import equiv_cert as ec
from hlith.obligation import symeq


def _exec(src: str, fn: str, *args):
    ns: dict = {}
    exec(compile(src, "<test>", "exec", dont_inherit=True), ns)
    try:
        return ("ret", ns[fn](*args))
    except BaseException as exc:  # noqa: BLE001
        return ("raise", type(exc).__name__)


def _must_refuse(base: str, post: str, fn: str = "f") -> None:
    assert not symeq.prove(base, post, fn).ok, "symeq.prove falsely proved a divergent pair"
    assert not ec.certify_sources(base, post, fn, module="m").ok, "equiv_cert falsely certified a divergent pair"


# -------------------------------------------------------------------------------------- eager default evaluation bugs
def test_dict_get_evaluates_default_eagerly_even_when_key_present():
    base = "def f(k: str):\n    d = {'a': 1}\n    return d.get(k, 1 // 0)\n"
    post = "def f(k: str):\n    d = {'a': 1}\n    return d[k] if k in d else (1 // 0)\n"
    assert _exec(base, "f", "a") == ("raise", "ZeroDivisionError")
    assert _exec(post, "f", "a") == ("ret", 1)
    _must_refuse(base, post)


def test_dict_get_default_side_effect_cannot_be_skipped():
    base = "def f(k: str, g):\n    d = {'a': 1}\n    return d.get(k, g(k))\n"
    post = "def f(k: str, g):\n    d = {'a': 1}\n    return d[k] if k in d else g(k)\n"
    log = []
    def side_eff(x):
        log.append(x)
        return 0
    _exec(base, "f", "a", side_eff)
    assert log == ["a"]
    log.clear()
    _exec(post, "f", "a", side_eff)
    assert log == []
    _must_refuse(base, post)


def test_min_and_max_evaluate_default_keyword_eagerly():
    for op in ("min", "max"):
        base = f"def f(x: int):\n    return {op}([x], default=1 // 0)\n"
        post = "def f(x: int):\n    return x\n"
        assert _exec(base, "f", 5) == ("raise", "ZeroDivisionError")
        assert _exec(post, "f", 5) == ("ret", 5)
        _must_refuse(base, post)


# -------------------------------------------------------------------------------------- unhashable key on empty dict/set
@pytest.mark.parametrize("base,post", [
    ("def f(x: int):\n    return [] in {}\n", "def f(x: int):\n    return False\n"),
    ("def f(x: int):\n    return {}.get([], 1)\n", "def f(x: int):\n    return 1\n"),
    ("def f(x: int):\n    d = {}\n    try:\n        return d[[]]\n    except KeyError:\n        return 0\n",
     "def f(x: int):\n    return 0\n"),
])
def test_unhashable_lookup_in_empty_mapping_raises_typeerror(base, post):
    assert _exec(base, "f", 0) == ("raise", "TypeError")
    assert _exec(post, "f", 0)[0] == "ret"
    _must_refuse(base, post)


# -------------------------------------------------------------------------------------- arity & overflow bugs
@pytest.mark.parametrize("expr", ["s.startswith()", "s.endswith()", "s.find()", "s.rfind()", "s.count()",
                                  "s.removeprefix()", "s.removesuffix()", "s.replace('a')", "s.lower('x')"])
def test_wrong_arity_str_method_is_not_total(expr):
    base = f"def f(s: str):\n    return s == 'ok' or bool({expr})\n"
    post = f"def f(s: str):\n    return bool({expr}) or s == 'ok'\n"
    assert _exec(base, "f", "ok") == ("ret", True)
    assert _exec(post, "f", "ok") == ("raise", "TypeError")
    _must_refuse(base, post)


@pytest.mark.parametrize("expr", ["'a' * n", "[1] * n", "2 ** n"])
def test_unbounded_repeat_or_pow_can_overflow_and_is_not_dead_code(expr):
    base = f"def f(n: int):\n    _ = {expr}\n    return 1\n"
    post = "def f(n: int):\n    return 1\n"
    _must_refuse(base, post)


def test_list_insert_huge_index_raises_overflowerror():
    base = "def f(n: int):\n    xs = []\n    xs.insert(n, 1)\n    return 1\n"
    post = "def f(n: int):\n    return 1\n"
    assert _exec(base, "f", 10 ** 30) == ("raise", "OverflowError")
    assert _exec(post, "f", 10 ** 30) == ("ret", 1)
    _must_refuse(base, post)


# -------------------------------------------------------------------------------------- proxy isinstance & mutable closure
def test_isinstance_on_opaque_object_is_world_observable():
    base = "def f(x, y):\n    a = isinstance(x, int)\n    b = isinstance(y, int)\n    return a and b\n"
    post = "def f(x, y):\n    b = isinstance(y, int)\n    a = isinstance(x, int)\n    return a and b\n"
    log = []

    class Proxy:
        def __init__(self, tag):
            self._tag = tag

        @property
        def __class__(self):
            log.append(self._tag)
            return int

    log.clear()
    _exec(base, "f", Proxy("x"), Proxy("y"))
    seq_b = list(log)
    log.clear()
    _exec(post, "f", Proxy("x"), Proxy("y"))
    seq_p = list(log)
    assert seq_b == ["x", "y"] and seq_p == ["y", "x"]
    _must_refuse(base, post)


def test_closure_capturing_mutable_local_list_cannot_be_ignored():
    base = "def f(x: int):\n    xs = [1]\n    def mut():\n        xs.append(2)\n    mut()\n    return len(xs)\n"
    post = "def f(x: int):\n    xs = [1]\n    def mut():\n        xs.append(2)\n    mut()\n    return 1\n"
    assert _exec(base, "f", 0) == ("ret", 2)
    assert _exec(post, "f", 0) == ("ret", 1)
    _must_refuse(base, post)


# -------------------------------------------------------------------------------------- assert -O & nested def/lambda eval
def test_assert_type_never_narrows_in_strict_mode():
    base = "def f(s: str) -> bool:\n    assert type(s) is str\n    return bool(s.startswith('a') or s.endswith('b'))\n"
    post = "def f(s: str) -> bool:\n    assert type(s) is str\n    return bool(s.endswith('b') or s.startswith('a'))\n"
    assert not symeq.prove(base, post, "f", modes=("any",)).ok
    assert not ec.certify_sources(base, post, "f", module="m", strict_domain=True).ok


@pytest.mark.parametrize("post_snip,pep649_deferred", [
    ("    def g(a=1 // 0):\n        return a\n", False),
    ("    def g(a: 1 // 0):\n        return a\n", True),
    ("    _ = lambda a=1 // 0: a\n", False),
])
def test_nested_def_and_lambda_defaults_and_annotations_execute_at_creation(post_snip, pep649_deferred):
    import sys

    base = "def f(x):\n    return x\n"
    post = "def f(x):\n" + post_snip + "    return x\n"
    assert _exec(base, "f", 1) == ("ret", 1)
    if not pep649_deferred or sys.version_info < (3, 14):
        assert _exec(post, "f", 1) == ("raise", "ZeroDivisionError")
    _must_refuse(base, post)


# -------------------------------------------------------------------------------------- shadowed / unimported annotations
def test_shadowed_builtin_or_unimported_typing_annotation_is_not_trusted():
    base = "class int:\n    pass\n\ndef f(x: int):\n    return x + 1\n"
    post = "class int:\n    pass\n\ndef f(x: int):\n    return 1 + x\n"
    _must_refuse(base, post)
    b2 = "def f(xs: List[int]):\n    t = 0\n    for x in xs:\n        t += x\n    return t\n"
    p2 = "def f(xs: List[int]):\n    return sum(xs)\n"
    _must_refuse(b2, p2)


# -------------------------------------------------------------------------------------- non-Python sibling & subclass defense
def test_non_python_sibling_file_change_refuses_opaque_sym_proof(tmp_path):
    base = "from pathlib import Path\n\ndef f(p):\n    x = Path(p).read_text()\n    if x is None:\n        return ''\n    return x\n"
    post = "from pathlib import Path\n\ndef f(p):\n    x = Path(p).read_text()\n    return '' if x is None else x\n"
    for side, txt in (("base", "alpha"), ("post", "beta")):
        (tmp_path / side).mkdir()
        (tmp_path / side / "m.py").write_text(base if side == "base" else post)
        (tmp_path / side / "data.txt").write_text(txt)
    assert not ec.certify(tmp_path / "base", tmp_path / "post", "m", "f").ok


def test_changed_int_subclass_in_tree_refuses_even_for_r0(tmp_path):
    base_m = "def f(x: int):\n    return x * 2\n"
    post_m = "def f(x: int):\n    return 2 * x\n"
    for side, sub in (("base", "class Box(int):\n    pass\n"), ("post", "class Box(int):\n    def __mul__(self, o):\n        return 0\n")):
        (tmp_path / side).mkdir()
        (tmp_path / side / "m.py").write_text(base_m if side == "base" else post_m)
        (tmp_path / side / "sub.py").write_text(sub)
    c = ec.certify(tmp_path / "base", tmp_path / "post", "m", "f")
    assert not c.ok and "int subclass" in c.reason.lower()


# -------------------------------------------------------------------------------------- universal admissions (O2-3, R1-1)
def test_frozenset_string_digits_and_split_and_normal_form_are_universal():
    base = "import string\n\nFIRST = frozenset(string.digits)\n\n\ndef classify(x: str, first=FIRST) -> int:\n    return 1 if x and x[0] in first else 0\n"
    post = "import string\n\nFIRST = frozenset(string.digits)\n\n\ndef classify(x: str, first=FIRST) -> int:\n    if not x:\n        return 0\n    return 1 if x[0] in first else 0\n"
    c_id = ec.certify_sources(base, base, "classify", module="m", strict_domain=True)
    assert c_id.ok and c_id.domain == () and "R0" in c_id.rules
    c_rw = ec.certify_sources(base, post, "classify", module="m", strict_domain=True)
    assert c_rw.ok and c_rw.domain == () and "NORM" in c_rw.rules


def test_nested_def_and_static_non_dunder_getattr_admit_r0_rename_universally():
    base = (
        "def collect(src):\n"
        "    tree = (src,)\n"
        "    out = []\n"
        "    def visit(node):\n"
        "        v = getattr(node, 'value', None)\n"
        "        out.append(v)\n"
        "    visit(tree)\n"
        "    return out\n"
    )
    post = base.replace("tree = (src,)", "tree_value = (src,)").replace("visit(tree)", "visit(tree_value)")
    c = ec.certify_sources(base, post, "collect", module="m", strict_domain=True)
    assert c.ok and c.domain == () and "R0" in c.rules
    # Dynamic or dunder getattr still refused
    bad = base.replace("getattr(node, 'value', None)", "getattr(node, '__call__', None)")
    assert not ec.certify_sources(base, bad, "collect", module="m").ok


# -------------------------------------------------------------------------------------- adversarial round 2 regressions
@pytest.mark.parametrize("base,post,args", [
    ("def f(b: bool):\n    return str(sum([], b))\n",
     "def f(b: bool):\n    return str(int(b))\n", (True,)),
    ("def f(xs: list[int], b: bool):\n    return str(sum(xs, b))\n",
     "def f(xs: list[int], b: bool):\n    return str(sum(xs, int(b)))\n", ([], True)),
    ("def f(xs: list[float]):\n    return isinstance(sum(xs), float)\n",
     "def f(xs: list[float]):\n    return True\n", ([],)),
    ("def f(xs: list[float]):\n    return isinstance(sum(x for x in xs), float)\n",
     "def f(xs: list[float]):\n    return True\n", ([],)),
    ("def f(n: int):\n    _ = len(range(n))\n    return 1\n",
     "def f(n: int):\n    return 1\n", (10 ** 30,)),
    ("def f(x: int):\n    xs = []\n    xs.clear(1)\n    return 1\n",
     "def f(x: int):\n    return 1\n", (0,)),
    ("def f(x: int):\n    xs = []\n    xs.sort(reverse=1 // 0)\n    return 1\n",
     "def f(x: int):\n    return 1\n", (0,)),
    ("def f(x: int):\n    xs = []\n    try:\n        xs.pop('bad')\n    except IndexError:\n        return 1\n    return 2\n",
     "def f(x: int):\n    return 1\n", (0,)),
    ("def f(x: int):\n    xs = []\n    try:\n        xs.pop(0, 1)\n    except IndexError:\n        return 1\n    return 2\n",
     "def f(x: int):\n    return 1\n", (0,)),
])
def test_adversarial_round2_soundness_regressions(base, post, args):
    assert _exec(base, "f", *args) != _exec(post, "f", *args)
    _must_refuse(base, post)


def test_equiv_norm_str_pure_enforces_exact_method_arity():
    base = "def f(a: str, b: str):\n    return '{}:{}'.format(a.upper('x'), b.replace('y'))\n"
    post = "def f(a: str, b: str):\n    t = b.replace('y')\n    return f\"{a.upper('x')}:{t}\"\n"
    _must_refuse(base, post)

