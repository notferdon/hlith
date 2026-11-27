"""Z3 delta-relational check (F4): the 12 design review cases, design review's fallthrough falsifier, and invented falsifiers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hlith import delta_rel
from hlith.delta_rel import COUNTEREXAMPLE, PROVED, UNMODELED, check_callable, soundness_selftest

FIX = json.loads((Path(__file__).parent / "fixtures" / "f4_cases.json").read_text())
BASE, DELTA = FIX["base"], FIX["delta"]
CASES = {c["id"]: c for c in FIX["cases"]}
EXPECT = {  # design review: PROVED for A, COUNTEREXAMPLE for 07/08/10/12; UNMODELED for what is outside the fragment
    "01_A_valid": PROVED,
    "02_B_lt_flaw": COUNTEREXAMPLE, "03_H1_strip": UNMODELED, "04_H2_default300": COUNTEREXAMPLE,
    "05_H3_gt4096_stmt": COUNTEREXAMPLE, "06_H4_separate_cache_stmt": UNMODELED,
    "07_DISCONFIRM1_expr_in_live_stmt": COUNTEREXAMPLE, "08_DISCONFIRM2_elif_or_piggyback": COUNTEREXAMPLE,
    "09_DISCONFIRM3_bundled_state_in_live_stmt": UNMODELED, "10_DISCONFIRM4_refactor_alignment": COUNTEREXAMPLE,
    "11_DISCONFIRM5_delta_only_state_bundle": UNMODELED, "12_BOUND_shift128_subexpr_evader": COUNTEREXAMPLE,
}


@pytest.mark.parametrize("cid", sorted(CASES))
def test_guard_case(cid):
    r = check_callable(BASE, CASES[cid]["post"], "truncate", [DELTA])
    assert r.verdict == EXPECT[cid], (cid, r.verdict, r.reason)
    assert (r.verdict == COUNTEREXAMPLE) == bool(r.witness_inputs)  # a counterexample always carries a seed


def test_no_valid_change_is_ever_refuted_and_no_regression_is_ever_proved():
    for cid, c in CASES.items():
        v = check_callable(BASE, c["post"], "truncate", [DELTA]).verdict
        assert not (c["truth"] == "HELD" and v == COUNTEREXAMPLE) and not (c["truth"] == "REFUTED" and v == PROVED), cid


# ---- design review mandatory RED: the prototype dropped an uncovered fall-through path and said PROVED
_A = BASE.replace("def truncate(text: str, limit: int = 400) -> str:\n",
                  "def truncate(text: str, limit: int = 400) -> str:\n    if limit <= 0:\n        return \"\"\n")
_FALL = _A.replace('    return text[: limit - 1] + "…"\n', '    if len(text) < 16 * 256:\n        return text[: limit - 1] + "…"\n')


def test_fallthrough_is_a_counterexample_not_proved():
    assert check_callable(BASE, _A, "truncate", [DELTA]).verdict == PROVED
    r = check_callable(BASE, _FALL, "truncate", [DELTA])
    assert r.verdict == COUNTEREXAMPLE and r.witness_inputs[0]["post_outcome"][0] == "none"
    assert r.witness_inputs[0]["pre_outcome"][0] == "ret"  # kinds compared, not only values
    assert len(eval(r.witness_inputs[0]["path_literals"]["0"])) >= 4096


def test_missing_else_return_is_a_counterexample():
    pre = "def f(x: int) -> int:\n    if x > 0:\n        return 1\n    return 2\n"
    post = "def f(x: int) -> int:\n    if x > 0:\n        return 1\n    elif x < 0:\n        return 2\n"
    r = check_callable(pre, post, "f")
    assert r.verdict == COUNTEREXAMPLE and r.witness_inputs[0]["path_literals"] == {"0": "0"}
    assert r.witness_inputs[0]["post_outcome"][0] == "none"


def test_negative_slice_uses_python_semantics():
    pre = "def f(t: str, n: int) -> str:\n    return t[: n - 1]\n"
    clamp = "def f(t: str, n: int) -> str:\n    return t[: max(n - 1, 0)]\n"  # differs where n - 1 < 0
    r = check_callable(pre, clamp, "f")
    assert r.verdict == COUNTEREXAMPLE
    n = int(r.witness_inputs[0]["path_literals"]["1"])
    t = eval(r.witness_inputs[0]["path_literals"]["0"])
    assert t[: n - 1] != t[: max(n - 1, 0)]
    same = "def f(t: str, n: int) -> str:\n    return t[0 : n - 1]\n"
    assert check_callable(pre, same, "f").verdict == PROVED


def test_floor_division_negative_is_python_floor_not_truncation():
    pre = "def f(x: int) -> int:\n    return x // 2\n"
    trunc = "def f(x: int) -> int:\n    if x < 0:\n        return -((-x) // 2)\n    return x // 2\n"
    r = check_callable(pre, trunc, "f")
    assert r.verdict == COUNTEREXAMPLE
    x = int(r.witness_inputs[0]["path_literals"]["0"])
    assert x < 0 and x // 2 != -((-x) // 2)
    assert check_callable(pre, "def f(x: int) -> int:\n    return (x - x % 2) // 2\n", "f").verdict == PROVED


def test_early_raise_is_a_different_output_kind():
    pre = "def f(x: int) -> int:\n    return x\n"
    post = "def f(x: int) -> int:\n    if x < 0:\n        raise ValueError('neg')\n    return x\n"
    r = check_callable(pre, post, "f")
    assert r.verdict == COUNTEREXAMPLE and r.witness_inputs[0]["post_outcome"][0] == "raise"
    delta = {"id": "neg", "predicate": {"type": "expr", "expr": "x < 0"},
             "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}
    assert check_callable(pre, post, "f", [delta]).verdict == PROVED
    wrong = {**delta, "expected": {"kind": "raises", "exc_type": "builtins.KeyError"}}
    assert check_callable(pre, post, "f", [wrong]).verdict == COUNTEREXAMPLE


def test_shadowed_builtin_is_unmodeled():
    pre = "def f(t: str) -> int:\n    return len(t)\n"
    post = "def len(x):\n    return 0\n\ndef f(t: str) -> int:\n    return len(t)\n"
    assert check_callable(pre, post, "f").verdict == UNMODELED
    assert check_callable(pre, "def f(len: str) -> int:\n    return 0\n", "f").verdict == UNMODELED


def test_unsupported_semantics_are_never_a_pass():
    for body in ("return t.upper()", "return int(t == t)", "x = 1\n    return x", "return t[::2]", "return t[0]"):
        post = f"def f(t: str) -> str:\n    {body}\n"
        assert check_callable("def f(t: str) -> str:\n    return t\n", post, "f").verdict == UNMODELED, body
    assert check_callable("def f(x: int) -> int:\n    return x\n",
                          "def f(x: int) -> int:\n    return x // -2\n", "f").verdict == UNMODELED  # not exact


def test_bool_int_coercion_is_not_conflated():
    pre = "def f(x: int) -> int:\n    return 1\n"
    assert check_callable(pre, "def f(x: int) -> bool:\n    return True\n", "f").verdict == UNMODELED


def test_counterexample_seed_is_executable_against_the_real_functions():
    r = check_callable(BASE, CASES["07_DISCONFIRM1_expr_in_live_stmt"]["post"], "truncate", [DELTA])
    lits = r.witness_inputs[0]["path_literals"]
    args = [eval(lits[str(i)]) for i in range(r.witness_inputs[0]["n_positional"])]
    pre, post = {}, {}
    exec(BASE, pre)
    exec(CASES["07_DISCONFIRM1_expr_in_live_stmt"]["post"], post)
    assert pre["truncate"](*args) != post["truncate"](*args)  # runtime, not solver


# ---- soundness self-test: the encoded semantics must equal the real runtime
@pytest.mark.parametrize("cid", ["base", "01_A_valid", "02_B_lt_flaw", "07_DISCONFIRM1_expr_in_live_stmt",
                                 "12_BOUND_shift128_subexpr_evader"])
def test_encoded_semantics_equal_runtime(cid):
    src = BASE if cid == "base" else CASES[cid]["post"]
    assert soundness_selftest(src, "truncate", n=40, seed=3) == []


@pytest.mark.real
@pytest.mark.parametrize("cid", ["base", "01_A_valid", "05_H3_gt4096_stmt", "08_DISCONFIRM2_elif_or_piggyback",
                                 "10_DISCONFIRM4_refactor_alignment", "12_BOUND_shift128_subexpr_evader"])
def test_encoded_semantics_equal_runtime_2000(cid):
    src = BASE if cid == "base" else CASES[cid]["post"]
    assert soundness_selftest(src, "truncate", n=2000, seed=11) == []


def test_selftest_catches_a_silent_abstraction_error(monkeypatch):
    monkeypatch.setattr(delta_rel, "_s_concat", lambda a, b: delta_rel._S.__call__(
        a.n + b.n, delta_rel.z3.Lambda([delta_rel.z3.Int("i")], delta_rel.z3.Select(b.f, delta_rel.z3.Int("i")))))
    assert soundness_selftest(BASE, "truncate", n=40, seed=3) != []


# ---- finding 25 (review cac7b49): the string content domain must be the FULL Python domain, never printable ASCII
_F25_BASE = 'def f(s: str) -> bool:\n    return s[0:1] == {c}\n'


@pytest.mark.parametrize("ch", [" ", "\t", "\n", "\x00", "\x7f", "é", "\u2028", "\ud800", "\U0001f600", "\x1f"])
def test_finding25_a_branch_on_any_character_is_never_proved_equal_to_a_constant(ch):
    base = _F25_BASE.format(c=repr(ch))
    post = "def f(s: str) -> bool:\n    return False\n"
    ns: dict = {}
    exec(base, ns)
    assert ns["f"](ch) is True  # real Python: the two functions DIVERGE on this input
    res = check_callable(base, post, "f", [])
    assert res.verdict == COUNTEREXAMPLE, (ch, res.verdict, res.reason)
    w = res.witness_inputs[0]
    assert eval(w["path_literals"]["0"])[0:1] == ch  # the witness is the real offending input


def test_finding25_empty_and_long_strings_are_in_the_domain():
    # empty string: s[0:1] == '' is True, so `not s` and `s[0:1] == ''` agree; a patch that breaks it is seen
    pre = "def f(s: str) -> bool:\n    return s[0:1] == ''\n"
    assert check_callable(pre, pre.replace("== ''", "== ''"), "f", []).verdict == PROVED
    assert check_callable(pre, "def f(s: str) -> bool:\n    return len(s) == 0\n", "f", []).verdict == PROVED  # exact equal
    assert check_callable(pre, "def f(s: str) -> bool:\n    return len(s) < 2\n", "f", []).verdict == COUNTEREXAMPLE


def test_finding25_oracle_sampler_reaches_the_special_characters():
    import random

    from hlith.delta_rel import string_sampler

    rs = string_sampler(random.Random(7), [])
    got = [rs() for _ in range(5000)]
    chars = {c for g in got for c in g}
    for must in (" ", "\t", "\n", "\r", "\x00", "\x7f", "\u2028", "\ud800", "\U0001f600", "\U0010ffff", "\u200b"):
        assert must in chars, repr(must)
    assert "" in got and any(len(g) >= 4095 for g in got) and any(len(g) == 1 and not g.isalnum() for g in got)


def test_finding25_domain_assumptions_are_stated_not_hidden():
    # PROVED is over the ANNOTATED types; a float/NaN argument is outside it, and the reason says so
    res = check_callable("def f(x: int) -> bool:\n    return x == x\n", "def f(x: int) -> bool:\n    return True\n", "f", [])
    assert res.verdict == PROVED and "annotated int/str/bool types" in res.reason and "Python ==" in res.reason
    assert (float("nan") == float("nan")) is False  # what the annotated-domain statement excludes


@pytest.mark.parametrize("post_body", [
    "return t[::-1]", "return t[::2]", "return t[0]", "return t.encode()", "return b'a'", "return 1.5",
    "return t * 2", "return t % 2", "return -t",
])
def test_finding25_unsupported_domain_features_are_unmodeled_not_guessed(post_body):
    pre = "def f(t: str) -> str:\n    return t\n"
    res = check_callable(pre, f"def f(t: str) -> str:\n    {post_body}\n", "f", [])
    assert res.verdict == UNMODELED, (post_body, res.verdict)
    assert check_callable("def f(x: int) -> int:\n    return x\n", "def f(x: int) -> int:\n    return x << 5000\n", "f", []).verdict == UNMODELED


def test_finding25_len_counts_code_points_incl_surrogates_and_non_bmp():
    pre = "def f(s: str) -> bool:\n    return len(s) == 1\n"
    post = "def f(s: str) -> bool:\n    return s[1:] == '' and s[0:1] != ''\n"
    assert check_callable(pre, post, "f", []).verdict == PROVED
    ns: dict = {}
    exec(pre, ns)
    assert ns["f"]("\U0001f600") and ns["f"]("\ud800")  # one code point each, as the encoding counts
    from hlith.delta_rel import soundness_selftest
    assert soundness_selftest(pre, "f", n=400, seed=2) == [] and soundness_selftest(post, "f", n=400, seed=2) == []


def test_finding25_selftest_catches_a_restricted_alphabet(monkeypatch):
    # in-process twin: the monkeypatch must reach the encoder (the public call runs in a forked worker)
    # the old defect, re-introduced: constrain parameter strings to printable ASCII inside the encoding
    from hlith import delta_rel as D

    real = D._domain

    def restricted(xs):
        i = D.z3.Int("i_r")
        extra = [D.z3.ForAll([i], D.z3.Implies(D.z3.And(i >= 0, i < x.n), D.z3.And(
            D.z3.Select(x.f, i) >= 33, D.z3.Select(x.f, i) <= 126))) for x in xs.values() if isinstance(x, D._S)]
        return real(xs) + extra

    monkeypatch.setattr(D, "_domain", restricted)
    res = D._check_callable_inproc('def f(s: str) -> bool:\n    return s[0:1] == " "\n', "def f(s: str) -> bool:\n    return False\n", "f", [])
    assert res.verdict == PROVED  # the regression this test pins: the restricted domain gives a FALSE proof ...
    monkeypatch.undo()
    assert D._check_callable_inproc('def f(s: str) -> bool:\n    return s[0:1] == " "\n', "def f(s: str) -> bool:\n    return False\n", "f", []).verdict == COUNTEREXAMPLE


# ---- numeric mode applies the same out-of-body rules as UF mode (found by the widened false-proof hunt)
def test_numeric_mode_docstring_annotation_and_import_time_changes_are_not_proved():
    pre = 'def f(x: int) -> int:\n    """Add one."""\n    return x + 1\n'
    assert check_callable(pre, pre, "f", []).verdict == PROVED
    assert check_callable(pre, pre.replace("Add one.", "Add two."), "f", []).verdict == UNMODELED
    assert check_callable(pre, pre.replace("-> int", "-> int | None"), "f", []).verdict == UNMODELED
    assert check_callable(pre, pre.replace("-> int", "-> int & None"), "f", []).verdict == UNMODELED
    assert check_callable(pre, pre + "register(f)\n", "f", []).verdict == UNMODELED
    assert check_callable(pre, "import hooks\nhooks.install()\n" + pre, "f", []).verdict == UNMODELED
