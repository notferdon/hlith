# SPDX-License-Identifier: Apache-2.0
"""review's OWN falsifiers for the generic contract classes review reported as witnessed false-HELDs on the d333be8f gate (written from the CLASS descriptions only; review's cases were not seen):
a rewrite of a regex pattern text, a repeat bound (literal, module constant, open-lower {,n}, sub-100), an anchor/flag change, lazy<->eager evaluation, a broadened or narrowed
except clause, and float regrouping with no type annotation. The certificate must REFUSE each by construction: there is no certified rule for any of them, so the refusal is
the absence of a rule, not the detection of a pattern. Each negative also asserts a NAMED reason. Controls (identical modulo renaming) prove the kernel is not refuse-everything."""

from __future__ import annotations

import pytest

from hlith.obligation import equiv_cert as ec

RE = "import re\n\n\n"


def refuse(base, post, fn="f", module="m"):
    c = ec.certify_sources(base, post, fn, module=module)
    assert not c.ok, ("ADMITTED a change that has no certified rule", c.rules, c.detail)
    assert c.reason, "a refusal must carry a named reason"
    return c


def admit(base, post, fn="f", module="m"):
    c = ec.certify_sources(base, post, fn, module=module)
    assert c.ok, (c.reason, c.detail)
    return c


# ----------------------------------------------------------------------------------------------- regex pattern text (even a semantically EQUIVALENT rewrite has no rule)
@pytest.mark.parametrize("b,p", [
    (r"a+", r"a{1,}"), (r"x", r"[x]"), (r"\d", r"[0-9]"), (r"ab|cd", r"(?:ab|cd)"), (r"a.b", r"a[^\n]b"), (r"(a)(b)", r"(a)(?:b)"),
])
def test_a_rewrite_of_an_inline_regex_pattern_has_no_rule(b, p):
    H = RE + "def f(s: str):\n    return bool(re.search(r'%s', s))\n"
    refuse(H % b, H % p)


@pytest.mark.parametrize("b,p", [(r"a+", r"a{1,}"), (r"x", r"[x]")])
def test_a_rewrite_of_a_module_regex_pattern_has_no_rule(b, p):
    H = RE + "_P = re.compile(r'%s')\n\n\ndef f(s: str):\n    return bool(_P.search(s))\n"
    refuse(H % b, H % p)


# ----------------------------------------------------------------------------------------------- repeat bounds in every spelling
@pytest.mark.parametrize("b,p", [("a{2,5}", "a{2,6}"), ("a{2,}", "a{2,9}"), ("a{,5}", "a{,6}"), ("a{25,30}", "a{25,31}"), ("a{3}", "a{4}"), ("a{100,104}", "a{100,105}"),
                                  ("a{1,2}b{3,4}", "a{1,2}b{3,5}")])
def test_a_changed_repeat_bound_in_an_inline_pattern_is_refused(b, p):
    H = RE + "def f(s: str):\n    return bool(re.fullmatch(r'%s', s))\n"
    refuse(H % b, H % p)


@pytest.mark.parametrize("b,p", [("a{2,5}", "a{2,6}"), ("a{,5}", "a{,6}"), ("a{100,104}", "a{100,105}")])
def test_a_changed_repeat_bound_in_a_module_constant_pattern_is_refused(b, p):
    H = RE + "_PAT = r'%s'\n\n\ndef f(s: str):\n    return bool(re.fullmatch(_PAT, s))\n"
    refuse(H % b, H % p)


def test_a_changed_repeat_bound_in_a_compiled_module_regex_is_refused():
    H = RE + "_R = re.compile(r'a{2,%s}')\n\n\ndef f(s: str):\n    return bool(_R.fullmatch(s))\n"
    refuse(H % 5, H % 6)


def test_a_pattern_built_by_concatenation_cannot_be_certified_when_it_changes():
    base = "import re\n\n\ndef f(s: str, n: int):\n    return bool(re.fullmatch('a{1,' + str(n) + '}', s))\n"
    post = "import re\n\n\ndef f(s: str, n: int):\n    return bool(re.fullmatch('a{1,' + str(n + 1) + '}', s))\n"
    refuse(base, post)


# ----------------------------------------------------------------------------------------------- anchors, flags, match mode
def test_match_versus_fullmatch_versus_search_is_refused():
    H = RE + "def f(s: str):\n    return bool(re.%s(r'ab', s))\n"
    refuse(H % "match", H % "fullmatch")
    refuse(H % "match", H % "search")
    refuse(H % "fullmatch", H % "search")


@pytest.mark.parametrize("b,p", [(r"^ab$", r"^ab\Z"), (r"^ab$", r"ab"), (r"ab$", r"ab\Z"), (r"^ab", r"ab")])
def test_an_anchor_change_is_refused(b, p):
    H = RE + "def f(s: str):\n    return bool(re.search(r'%s', s))\n"
    refuse(H % b, H % p)


def test_a_flag_added_or_changed_is_refused():
    base = RE + "def f(s: str):\n    return bool(re.search(r'ab', s))\n"
    refuse(base, RE + "def f(s: str):\n    return bool(re.search(r'ab', s, re.I))\n")
    refuse(RE + "def f(s: str):\n    return bool(re.search(r'ab', s, re.I))\n", RE + "def f(s: str):\n    return bool(re.search(r'ab', s, re.M))\n")
    refuse(RE + "_R = re.compile(r'ab')\n\n\ndef f(s: str):\n    return bool(_R.search(s))\n", RE + "_R = re.compile(r'ab', re.I)\n\n\ndef f(s: str):\n    return bool(_R.search(s))\n")


# ----------------------------------------------------------------------------------------------- lazy <-> eager evaluation
@pytest.mark.parametrize("b,p", [
    ("any(g(x) for x in xs)", "any([g(x) for x in xs])"),
    ("all(g(x) for x in xs)", "all([g(x) for x in xs])"),
    ("sum(g(x) for x in xs)", "sum([g(x) for x in xs])"),
    ("next(iter(xs), None)", "list(xs)[0] if xs else None"),
])
def test_lazy_versus_eager_evaluation_is_refused(b, p):
    H = "def g(x):\n    return x\n\n\ndef f(xs: list):\n    return %s\n"
    refuse(H % b, H % p)


# ----------------------------------------------------------------------------------------------- except clauses
@pytest.mark.parametrize("b,p", [
    ("(ValueError, TypeError)", "Exception"),
    ("Exception", "(ValueError, TypeError)"),
    ("ValueError", "(ValueError, KeyError)"),
    ("(ValueError, TypeError)", "ValueError"),
    ("(ValueError, TypeError)", "BaseException"),
])
def test_a_broadened_or_narrowed_except_clause_is_refused(b, p):
    H = "def f(x):\n    try:\n        return int(x)\n    except %s:\n        return 0\n"
    refuse(H % b, H % p)


def test_an_added_bare_except_is_refused():
    refuse("def f(x):\n    try:\n        return int(x)\n    except ValueError:\n        return 0\n",
           "def f(x):\n    try:\n        return int(x)\n    except ValueError:\n        return 0\n    except:\n        return 1\n")


# ----------------------------------------------------------------------------------------------- float / untyped regrouping, and non-associative subtraction
@pytest.mark.parametrize("sig", ["a, b, c", "a: float, b: float, c: float"])
def test_regrouping_an_arithmetic_expression_is_refused_with_or_without_annotations(sig):
    refuse(f"def f({sig}):\n    return (a + b) + c\n", f"def f({sig}):\n    return a + (b + c)\n")
    refuse(f"def f({sig}):\n    return a * b * c\n", f"def f({sig}):\n    return a * (b * c)\n")
    refuse(f"def f({sig}):\n    return a - b - c\n", f"def f({sig}):\n    return a - (b - c)\n")


def test_exact_int_associativity_requires_scoped_domain_and_subtraction_stays_refused():
    sig = "a: int, b: int, c: int"
    # Non-associative subtraction is ALWAYS refused, even on exact ints.
    refuse(f"def f({sig}):\n    return a - b - c\n", f"def f({sig}):\n    return a - (b - c)\n")
    # Exact Python int (+, *) is arbitrary-precision associative on exact int/bool,
    # so SYM admits it ONLY in scoped exact-int domain (and refuses under strict_domain=True).
    for b_expr, p_expr in (("(a + b) + c", "a + (b + c)"), ("a * b * c", "a * (b * c)")):
        b = f"def f({sig}):\n    return {b_expr}\n"
        p = f"def f({sig}):\n    return {p_expr}\n"
        assert not ec.certify_sources(b, p, "f", module="m", strict_domain=True).ok
        c = admit(b, p)
        assert c.rules == ("SYM",) and dict(c.domain) == {"a": "int", "b": "int", "c": "int"}
        assert "exact builtin int" in c.domain_text and "outside this claim" in c.domain_text


def test_reordering_commutative_float_operands_is_refused():
    refuse("def f(a, b):\n    return a + b\n", "def f(a, b):\n    return b + a\n")


def test_a_rounding_composition_change_is_refused():
    refuse("def f(a: int, b: int) -> int:\n    return a // 10 + b // 10\n", "def f(a: int, b: int) -> int:\n    return (a + b) // 10\n")


# ----------------------------------------------------------------------------------------------- controls: the kernel is not refuse-everything
def test_control_identical_regex_module_with_renamed_locals_is_admitted():
    base = RE + "_P = re.compile(r'a{2,5}')\n\n\ndef f(s: str):\n    m = _P.search(s)\n    return bool(m)\n"
    post = RE + "_Q = re.compile(r'a{2,5}')\n\n\ndef f(s: str):\n    hit = _Q.search(s)\n    return bool(hit)\n"
    assert "R0" in admit(base, post).rules


def test_control_identical_lazy_and_except_code_is_admitted():
    src = "def g(x):\n    return x\n\n\ndef f(xs: list):\n    try:\n        return any(g(x) for x in xs)\n    except (ValueError, TypeError):\n        return False\n"
    assert "R0" in admit(src, src.replace("g(x) for x in xs", "g(y) for y in xs")).rules  # a comprehension variable renamed: not behaviour
    # a PARAMETER rename of the target is a public-interface change: refused
    refuse(src, src.replace("def f(xs: list)", "def f(items: list)").replace("for x in xs", "for x in items"))
