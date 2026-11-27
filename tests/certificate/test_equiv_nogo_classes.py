# SPDX-License-Identifier: Apache-2.0
"""NO-GO on 7e1926fc (maintainer + review + review), class-level fixes.

(A) DEFINITION-TIME SEMANTICS. Everything a `def` evaluates when the module runs - decorators, default values, annotations (before Python 3.14, or without `from __future__ import annotations`) - is
    behaviour (import-time). Strict whitelist for annotations: builtin type names the module does not rebind, None, string literals, `X | Y` of types (a string or number operand raises), and subscripts of
    KNOWN generics with VALID ARITY (list/set/frozenset/type[T], dict[K, V], tuple[T, ...] / tuple[T1, T2], typing.Optional/List/Set/FrozenSet/Type[T], Dict[K, V], Tuple[...], Union[...]);
    no calls, no user names, no malformed subscripts. And this applies to EVERY function the patch adds, removes or whose header changes - including a helper that NORM inlined away (it still runs its
    header at import) - not only to units in the dependency cone.
(B) DOMAIN CLOSURE. R2/R3 and the typed rules are claims over exact builtin parameters. Every path that is in-tree or checker-side is closed: the call-site scan now ALSO reads the repo's own test files,
    and a call-site argument that is provably not the domain type (a call of an in-tree class, or a literal of another type: bytes/None/int for a str parameter, ...) refuses. What remains open - and is
    stated in the operator sentence - is an OUTSIDE caller (not in the tree) passing a subclass or another type; see the design note in the commit message for the stricter option and its measured cost.
(C) R3/De Morgan atoms are pure and total only for exact builtin str; the certificate's atom whitelist is per-atom (str methods with literal arguments, `lit in p`, len(p) op int, module regex on p),
    nothing else reorders: asserted below together with the domain sentence."""

from __future__ import annotations

import pytest

from hlith.obligation import equiv_cert as ec

BASE = "def f(n):\n    return n + 1\n"


def cert(b, p, fn="f"):
    return ec.certify_sources(b, p, fn, module="m")


def ann_post(ann, imports=""):
    return imports + f"def f(n: {ann}):\n    return n + 1\n"


def ann_base(imports=""):
    return imports + BASE


# ----------------------------------------------------------------------------------------------- (A) annotation whitelist
TYP = "from typing import Optional, List, Dict, Tuple, Union, Callable, Any, Set, FrozenSet, Type\n\n\n"


@pytest.mark.parametrize("ann", [
    "int[str]", "str[int]", "list[int, str]", "dict[int]", "dict[int, str, bool]", "set[int, int]", "type[int, int]", "int | 5", "'int' | None", "None | 'x'", "list[int][str]",
    "foo()", "len(x)", "Undefined", "int.__add__", "(lambda: int)()", "[int for _ in range(2)]", "list[foo()]", "tuple[()]", "list[...]", "dict[str, ...]",
    "Optional[int, str]", "List[int, str]", "Dict[int]", "Callable[int, str]", "Foo[int]", "typing.Optional[int]", "Union[]",
])
def test_malformed_or_unknown_annotations_never_certify_as_annotation_only(ann):
    r = cert(ann_base(TYP), ann_post(ann, TYP))
    assert not r.ok, (ann, r.rules)


@pytest.mark.parametrize("ann", [
    "int", "str", "list[int]", "dict[str, int]", "tuple[int, ...]", "tuple[int, str]", "set[str]", "frozenset[int]", "type[int]", "int | None", "list[int] | None", "None",
    "'ForwardRef'", "Optional[int]", "List[int]", "Dict[str, int]", "Tuple[int, ...]", "Union[int, str]", "Set[str]", "Type[int]", "Any",
])
def test_whitelisted_annotations_certify(ann):
    r = cert(ann_base(TYP), ann_post(ann, TYP))
    assert r.ok and "ANN" in r.rules, (ann, r.reason, r.detail)


def test_a_helper_with_a_raising_annotation_inlined_away_is_still_refused():
    """The helper header RUNS at import in the post version even though the call was inlined: 1/0 raises ZeroDivisionError when the module loads."""
    base = "def f(n):\n    return n + 1\n"
    post = "def _h(x: 1 / 0):\n    return x + 1\n\n\ndef f(n):\n    return _h(n)\n"
    assert not cert(base, post).ok


@pytest.mark.parametrize("hdr", ["def _h(x=1 / 0):", "def _h(x=g()):", "@deco\ndef _h(x):", "def _h(x) -> Undefined:", "def _h(x: Undefined):"])
def test_an_added_helper_whose_definition_time_header_can_raise_or_act_is_refused(hdr):
    base = "def g():\n    return 1\n\n\ndef deco(f):\n    return f\n\n\ndef f(n):\n    return n + 1\n"
    post = "def g():\n    return 1\n\n\ndef deco(f):\n    return f\n\n\n" + hdr + "\n    return x + 1\n\n\ndef f(n):\n    return n + 1\n"
    assert not cert(base, post).ok, hdr


def test_an_added_helper_with_a_pure_header_is_fine():
    base = "def f(n):\n    return n + 1\n"
    post = "def _h(x: int = 0, *, y: 'str' = 'a', z=(1, 2)) -> int:\n    return x + 1\n\n\ndef f(n):\n    return n + 1\n"
    assert cert(base, post).ok


def test_a_changed_default_of_a_function_outside_the_cone_is_import_time_behaviour():
    base = "def g():\n    return 1\n\n\ndef other(x=g()):\n    return x\n\n\ndef f(n):\n    return n + 1\n"
    post = base.replace("x=g()", "x=g() + 1")
    assert not cert(base, post).ok


def test_an_unchanged_odd_header_outside_the_cone_is_not_a_problem():
    base = "def g():\n    return 1\n\n\ndef other(x=g()):\n    return x\n\n\ndef f(n):\n    return n + 1\n"
    assert cert(base, base.replace("n + 1", "1 + n")).ok is False  # (commutation has no rule) ...
    assert cert(base, base.replace("def f(n):", "def f(n: int):")).ok  # ... but an unrelated unchanged header never blocks an annotation-only edit


# ----------------------------------------------------------------------------------------------- (B) in-tree closure
S_BASE = "def f(s: str) -> bool:\n    return bool(s.startswith('x') or s.endswith('x'))\n"
S_POST = "def f(s: str) -> bool:\n    if s.endswith('x'):\n        return True\n    return bool(s.startswith('x'))\n"


def _tree(tmp_path, files):
    for side in ("base", "post"):
        for rel, text in files.items():
            body = text(side) if callable(text) else text
            p = tmp_path / side / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)


def _cert(tmp_path, extra):
    _tree(tmp_path, {"pkg/__init__.py": "", "pkg/m.py": lambda s: S_BASE if s == "base" else S_POST, **extra})
    return ec.certify(tmp_path / "base", tmp_path / "post", "pkg.m", "f")


@pytest.mark.parametrize("call", ["f(Loud('x'))", "f(b'123456')", "f(None)", "f(5)", "f(s=b'x')", "f([1])", "f({})"])
def test_the_repos_own_tests_feeding_a_non_str_refuse_r3(tmp_path, call):
    t = "from pkg.m import f\n\n\nclass Loud(str):\n    def startswith(self, p):\n        return False\n\n\ndef test_x():\n    assert " + call + " is not None\n"
    r = _cert(tmp_path, {"tests/test_m.py": t})
    assert not r.ok and "call site" in (r.reason + r.detail).lower(), (call, r.reason, r.detail)


def test_a_literal_of_another_type_in_a_non_test_call_site_refuses(tmp_path):
    r = _cert(tmp_path, {"pkg/use.py": "from pkg.m import f\n\n\ndef go():\n    return f(b'abc')\n"})
    assert not r.ok and "call site" in (r.reason + r.detail).lower(), (r.reason, r.detail)


def test_the_repos_tests_calling_with_plain_strs_keep_r3(tmp_path):
    t = "from pkg.m import f\n\n\ndef test_x():\n    assert f('x') is True\n    assert f('abc') is False\n"
    r = _cert(tmp_path, {"tests/test_m.py": t})
    assert r.ok and "R3" in r.rules, (r.reason, r.detail)


def test_int_domain_refuses_str_none_float_literals_but_admits_bool_and_int(tmp_path):
    base = "def f(a: int, b: int):\n    if a > 0:\n        if b > 0:\n            return a - b\n    return a\n"
    post = "def f(a: int, b: int):\n    if a <= 0 or b <= 0:\n        return a\n    return a - b\n"
    for bad in ("f('1', 2)", "f(None, 2)", "f(1.5, 2)", "f(1, b'2')"):
        _tree(tmp_path / bad.replace("'", "q").replace(" ", "_").replace("(", "").replace(")", "").replace(",", ""), {"pkg/__init__.py": "", "pkg/m.py": lambda s: base if s == "base" else post,
              "pkg/use.py": f"from pkg.m import f\n\n\ndef go():\n    return {bad}\n"})
        r = ec.certify(tmp_path / bad.replace("'", "q").replace(" ", "_").replace("(", "").replace(")", "").replace(",", "") / "base",
                       tmp_path / bad.replace("'", "q").replace(" ", "_").replace("(", "").replace(")", "").replace(",", "") / "post", "pkg.m", "f")
        assert not r.ok, bad
    _tree(tmp_path / "ok", {"pkg/__init__.py": "", "pkg/m.py": lambda s: base if s == "base" else post, "pkg/use.py": "from pkg.m import f\n\n\ndef go():\n    return f(3, True) + f(-1, 0)\n"})
    assert ec.certify(tmp_path / "ok" / "base", tmp_path / "ok" / "post", "pkg.m", "f").ok


# ----------------------------------------------------------------------------------------------- (C) per-atom purity under the exact domain
@pytest.mark.parametrize("post_atoms", [
    "bool(s.endswith('b') or s.startswith('a'))",
])
def test_demorgan_over_str_predicates_is_admitted_only_with_the_domain_sentence(post_atoms):
    base = "def f(s: str) -> bool:\n    return not (not s.startswith('a') and not s.endswith('b'))\n"
    post = f"def f(s: str) -> bool:\n    return {post_atoms}\n"
    r = cert(base, post)
    assert r.ok and "R3" in r.rules and dict(r.domain) == {"s": "str"}, (r.reason, r.detail)
    assert "exact builtin str" in r.domain_text and "outside this claim" in r.domain_text


@pytest.mark.parametrize("atom", ["s.custom('a')", "g(s)", "s[0] == 'a'"])
def test_atoms_outside_the_pure_total_whitelist_are_never_reordered(atom):
    base = f"def f(s: str, t: str = '', prefix: str = '') -> bool:\n    return bool({atom} or s.endswith('b'))\n"
    post = f"def f(s: str, t: str = '', prefix: str = '') -> bool:\n    return bool(s.endswith('b') or {atom})\n"
    assert not cert(base, post).ok, atom


def test_startswith_with_unannotated_prefix_is_never_reordered():
    base = "def f(s: str, prefix='') -> bool:\n    return bool(s.startswith(prefix) or s.endswith('b'))\n"
    post = "def f(s: str, prefix='') -> bool:\n    return bool(s.endswith('b') or s.startswith(prefix))\n"
    assert not cert(base, post).ok


@pytest.mark.parametrize("atom,need_prefix", [("s.startswith(prefix)", True), ("bool(s.find('a'))", False)])
def test_pure_exact_str_atoms_outside_r3_only_certify_via_sym_under_scoped_domain(atom, need_prefix):
    base = f"def f(s: str, t: str = '', prefix: str = '') -> bool:\n    return bool({atom} or s.endswith('b'))\n"
    post = f"def f(s: str, t: str = '', prefix: str = '') -> bool:\n    return bool(s.endswith('b') or {atom})\n"
    assert not ec.certify_sources(base, post, "f", module="m", strict_domain=True).ok
    r = cert(base, post)
    assert r.ok and r.rules == ("SYM",) and "R3" not in r.rules
    dom = dict(r.domain)
    assert dom.get("s") == "str" and (not need_prefix or dom.get("prefix") == "str")
    assert "exact builtin str" in r.domain_text and "outside this claim" in r.domain_text


# ----------------------------------------------------------------------------------------------- (B') the STRICT option: the domain must be SELF-ENFORCED by the target (opt-in switch, default off)
GUARDED_BASE = ("def f(s: str) -> bool:\n    if type(s) is not str:\n        raise TypeError('exact str only')\n    return bool(s.startswith('x') or s.endswith('x'))\n")
GUARDED_POST = ("def f(s: str) -> bool:\n    if type(s) is not str:\n        raise TypeError('exact str only')\n    if s.endswith('x'):\n        return True\n    return bool(s.startswith('x'))\n")


def test_strict_mode_refuses_a_domain_rule_whose_target_does_not_enforce_the_type_itself():
    r = ec.certify_sources(S_BASE, S_POST, "f", module="m", strict_domain=True)
    assert not r.ok and "self-enforce" in (r.reason + r.detail).lower(), (r.reason, r.detail)
    assert ec.certify_sources(S_BASE, S_POST, "f", module="m", strict_domain=False).ok  # the default is unchanged


def test_strict_mode_admits_it_when_the_target_enforces_exact_str_at_entry():
    r = ec.certify_sources(GUARDED_BASE, GUARDED_POST, "f", module="m", strict_domain=True)
    assert r.ok, (r.reason, r.detail)


@pytest.mark.parametrize("guard", ["    if isinstance(s, str):\n        pass\n", "    if type(s) is str:\n        pass\n", "    assert type(s) is str\n"])
def test_strict_mode_does_not_accept_weaker_or_non_terminating_guards(guard):
    b = S_BASE.replace("    return bool", guard + "    return bool")
    p = S_POST.replace("    if s.endswith", guard + "    if s.endswith")
    r = ec.certify_sources(b, p, "f", module="m", strict_domain=True)
    assert not r.ok, guard


def test_strict_mode_leaves_domain_free_rules_alone():
    r = ec.certify_sources("def f(a):\n    return a + 1\n", "def f(b):\n    return b + 1\n".replace("b", "a"), "f", module="m", strict_domain=True)
    assert r.ok
