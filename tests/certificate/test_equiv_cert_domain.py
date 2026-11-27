# SPDX-License-Identifier: Apache-2.0
"""DOMAIN of a certified HELD (maintainer/design review counterexample 2026-11-23 10:00: a str SUBCLASS overriding startswith/endswith separates R3's reordered pair). A bare annotation is not
runtime enforcement and Hlith binds no caller type, so the premise must be an EXPLICIT, evidence-retained DOMAIN of the claim, with the checkable parts enforced:

  * R2/R3 are claims over EXACT BUILTIN parameter types (the annotation names them); the Cert carries that domain and its text, and the HELD claim/evidence show it;
  * an in-tree `class X(str)` makes the exact-str premise false for in-tree callers: R2/R3 are refused (named reason);
  * when a target parameter is OPEN (unannotated / not an exact builtin) and the same patch changes ANY in-tree class, dispatch targets can differ: refused for every rule;
  * R0 (identical code) and R4 (AST nodes of ast.parse output) need no input-type assumption: executed below on hostile objects to show they stay equal.

This file is generic: it attacks the PREMISE (type exactness, overridden methods, __eq__/__contains__/__len__/__bool__ side effects, bytes vs str, property/descriptor args) for every
rule, not one fixture. No differential run, no slot."""

from __future__ import annotations

import pytest

from hlith.obligation import equiv_cert as ec

R3_OLD = 'def f(s: str) -> bool:\n    return bool(s.startswith("x") or s.endswith("x"))\n'
R3_NEW = 'def f(s: str) -> bool:\n    if s.endswith("x"):\n        return True\n    return bool(s.startswith("x"))\n'
R2_OLD = "def f(s: str) -> int:\n    return len(s)\n"
R2_NEW = "def f(s: str) -> int:\n    if 'x' in s:\n        raise ValueError('x')\n    return len(s)\n"
R2_DELTA = [{"id": "d", "symbol": "m.f", "type": "expr", "param": "s", "expr": "isinstance(s, str) and 'x' in s", "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}]


def cert(base, post, deltas=(), fn="f"):
    return ec.certify_sources(base, post, fn, deltas=deltas, module="m")


# ================================================================================================ the domain is a first-class, retained part of the Cert
def test_r3_certificate_carries_an_explicit_exact_builtin_domain():
    c = cert(R3_OLD, R3_NEW)
    assert c.ok and "R3" in c.rules
    assert dict(c.domain) == {"s": "str"}, c.domain
    t = c.domain_text.lower()
    assert "exact builtin" in t and "subclass" in t and "outside" in t, c.domain_text


def test_r2_certificate_carries_an_explicit_exact_builtin_domain():
    c = cert(R2_OLD, R2_NEW, R2_DELTA)
    assert c.ok and "R2" in c.rules
    assert dict(c.domain) == {"s": "str"}, c.domain
    assert "exact builtin" in c.domain_text


def test_r0_identity_needs_no_input_type_assumption_so_it_claims_none():
    c = cert("def f(x):\n    return x\n", "def f(x):\n    return x\n")
    assert c.ok and c.rules == ("R0",) and c.domain == (), c.domain
    assert "identical" in c.domain_text.lower()


# ================================================================================================ the checkable premise is enforced
@pytest.mark.parametrize("old,new,deltas", [(R3_OLD, R3_NEW, ()), (R2_OLD, R2_NEW, R2_DELTA)])
def test_an_in_tree_str_subclass_refuses_the_exact_str_rules(old, new, deltas):
    sub = "\n\nclass Loud(str):\n    def startswith(self, p):\n        return True\n"
    c = cert(old + sub, new + sub, deltas)
    assert not c.ok and "str subclass" in (c.reason + c.detail).lower(), (c.reason, c.detail)


def test_an_in_tree_str_subclass_unchanged_does_not_hurt_identity():
    sub = "\n\nclass Loud(str):\n    def startswith(self, p):\n        return True\n"
    assert cert("def f(x):\n    return x\n" + sub, "def f(x):\n    return x\n" + sub).ok


def test_a_changed_str_subclass_refuses_even_identity():
    base = "def f(x):\n    return x\n\n\nclass Loud(str):\n    def startswith(self, p):\n        return True\n"
    post = base.replace("return True", "return False")
    c = cert(base, post)
    assert not c.ok and "class" in (c.reason + c.detail).lower(), (c.reason, c.detail)


def test_an_open_parameter_plus_a_changed_in_tree_class_is_refused_for_every_rule():
    base = "class K:\n    def m(self):\n        return 1\n\n\ndef f(obj):\n    return obj.m()\n"
    post = base.replace("return 1", "return 2")
    c = cert(base, post)
    assert not c.ok and "open" in (c.reason + c.detail).lower(), (c.reason, c.detail)


def test_an_open_parameter_with_an_unchanged_class_is_identity_admitted():
    src = "class K:\n    def m(self):\n        return 1\n\n\ndef f(obj):\n    return obj.m()\n"
    assert cert(src, src).ok


def test_closed_builtin_parameters_are_unaffected_by_an_unrelated_class_change():
    base = "class K:\n    def m(self):\n        return 1\n\n\ndef f(n: int) -> int:\n    return n + 1\n"
    assert cert(base, base.replace("return 1", "return 2")).ok


# ================================================================================================ executed unknown-type matrix (which rules are sound outside the exact domain, which are not)
class _Str(str):
    """A str subclass with side-effecting overrides (maintainer's shape, generalised)."""
    def __new__(cls, v):
        o = super().__new__(cls, v)
        o.log = []
        return o

    def startswith(self, *a):
        self.log.append("start")
        return False

    def endswith(self, *a):
        self.log.append("end")
        return len(self.log) == 1

    def __contains__(self, item):
        self.log.append("in")
        return True

    def __len__(self):
        self.log.append("len")
        return 99

    def __eq__(self, other):
        self.log.append("eq")
        return True

    __hash__ = str.__hash__


class _Prop:
    @property
    def s(self):
        raise RuntimeError("descriptor")


class _Truthy:
    def __init__(self):
        self.n = 0

    def __bool__(self):
        self.n += 1
        return self.n % 2 == 0


def _run(src, fn, arg):
    ns = {}
    exec(src, ns)
    try:
        return ("ret", ns[fn](arg))
    except BaseException as e:  # noqa: BLE001
        return ("raise", type(e).__name__)


HOSTILE = [("str-subclass-overrides", lambda: _Str("x")), ("bytes", lambda: b"x"), ("int", lambda: 7), ("property-object", lambda: _Prop()), ("side-effecting-bool", lambda: _Truthy()), ("None", lambda: None)]


@pytest.mark.parametrize("name,mk", HOSTILE, ids=[h[0] for h in HOSTILE])
def test_r0_identity_is_equal_on_every_hostile_object(name, mk):
    src = "def f(s):\n    return bool(s.startswith('x') or s.endswith('x'))\n"
    a, b = mk(), mk()
    assert _run(src, "f", a) == _run(src.replace("(s)", "(s)"), "f", b)  # identical code: identical behaviour on ANY object


def test_r3_external_subclass_callers_are_outside_the_admitted_domain_by_stated_contract_and_in_tree_feeds_are_refused():
    """The reordered pair really differs on a hostile str SUBCLASS. Where an IN-TREE path can feed one the certificate REFUSES (test_equiv_cert_enforced_domain); the case that remains ok is
    a caller OUTSIDE the tree, which is outside the admitted domain by contract and the sentence the operator reads says so (and what is enforced)."""
    c = cert(R3_OLD, R3_NEW)
    assert c.ok and dict(c.domain) == {"s": "str"}
    assert _run(R3_OLD, "f", _Str("x")) != _run(R3_NEW, "f", _Str("x"))  # the external subclass case is genuinely divergent ...
    t = c.domain_text
    assert "outside this claim" in t and "enforced" in t and "no in-tree call site" in t and "subclass" in t, t  # ... and the claim says it does not cover it


def test_r2_external_subclass_callers_are_outside_the_admitted_domain_by_stated_contract():
    c = cert(R2_OLD, R2_NEW, R2_DELTA)
    assert c.ok and dict(c.domain) == {"s": "str"}
    assert _run(R2_OLD, "f", _Str("abc")) != _run(R2_NEW, "f", _Str("abc"))  # __contains__ override fires the guard on a value that has no 'x'
    assert "outside this claim" in c.domain_text


def test_exact_builtin_str_inputs_agree_for_r3_and_r2_inside_the_domain():
    for s in ("", "x", "ax", "xa", "axb", "abc"):
        assert _run(R3_OLD, "f", s) == _run(R3_NEW, "f", s)
    for s in ("", "abc", "x"):
        old, new = _run(R2_OLD, "f", s), _run(R2_NEW, "f", s)
        assert old == new or ("x" in s and new == ("raise", "ValueError"))  # outside the approved predicate: identical; inside: exactly the approved raise


def test_r4_depends_on_ast_parse_output_not_on_the_argument_type():
    """R4's atoms read exact ast nodes produced by ast.parse in the function, so hostile argument OBJECTS reach only ast.parse's own argument handling, identically on both sides."""
    base = ('import ast\n\n\ndef f(src: str):\n    tree = ast.parse(src)\n    nodes = sorted((n for n in ast.walk(tree) if isinstance(n, ast.Call)), key=lambda n: n.lineno)\n'
            '    out = []\n    for node in nodes:\n        try:\n            pos = [ast.literal_eval(a) for a in node.args]\n        except (ValueError, TypeError, SyntaxError, RecursionError):\n            continue\n'
            '        if any(isinstance(a, ast.Starred) for a in node.args):\n            continue\n        out.append(pos)\n    return out\n')
    post = base.replace("        try:\n", "        if any(isinstance(a, ast.Starred) for a in node.args):\n            continue\n        try:\n").replace(
        "            continue\n        out.append(pos)", "            continue\n        out.append(pos)", 1)
    # remove the trailing (now redundant) skip after the try, as the real patch does
    post = post.replace("        if any(isinstance(a, ast.Starred) for a in node.args):\n            continue\n        out.append(pos)", "        out.append(pos)")
    c = cert(base, post)
    assert c.ok and "R4" in c.rules, (c.reason, c.detail)
    for arg in ("g(1, 2)\n", "g(*x)\n", "g(1)\ng(*y)\n", _Str("g(3)\n")):
        assert _run(base, "f", arg) == _run(post, "f", arg)


# ================================================================================================ utility: module-level conditional defs / try-import blocks (real repos have them)
WIN = ("import sys\n\nif sys.platform == 'win32':\n    def reg(h):\n        try:\n            import winreg\n        except ImportError:\n            return False\n        return winreg.X\n\n\n"
       "def f(s: str):\n    return s.strip()\n")


def test_a_module_level_conditional_def_does_not_make_identity_unavailable():
    c = cert(WIN, WIN)
    assert c.ok and c.rules == ("R0",), (c.reason, c.detail)  # was 'unresolved global name winreg' (requests.utils): identical source refused


def test_an_edit_inside_a_module_level_conditional_def_is_still_refused():
    c = cert(WIN, WIN.replace("winreg.X", "winreg.Y"))
    assert not c.ok and "module-level statements differ" in c.reason, (c.reason, c.detail)


def test_import_time_expressions_of_a_nested_def_still_reach_the_cone():
    src = "def helper(x):\n    return x\n\n\nif True:\n    def g(a=helper(1)):\n        return a\n\n\ndef f(s: str):\n    return s\n"
    c = cert(src, src.replace("return x", "return x + 1", 1))
    assert not c.ok, c.rules  # a default argument RUNS at import: a changed helper it calls is not equivalent


def test_a_module_level_try_import_fallback_is_admitted_when_identical_and_refused_when_edited():
    src = "try:\n    import json\nexcept ImportError:\n    json = None\n\n\ndef f(s: str):\n    return s.strip()\n"
    assert cert(src, src).ok
    assert not cert(src, src.replace("json = None", "json = 0")).ok
