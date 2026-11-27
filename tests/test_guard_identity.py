# SPDX-License-Identifier: Apache-2.0
"""Guard identity for delta coverage (design review F-C1) and removed entry guards.

A delta that covers one ValueError guard must not cover another. The oracle here is EXECUTION: the real function is
run over a grid of inputs and each raise is attributed to its guard by the traceback line; `eval` of the guard and
of the delta predicate decides membership. It shares no code with delta_cover or with drive_inputs.
"""
import traceback

import pytest

from hlith.delta_cover import guard_coverage, removed_guard_coverage

EXC = "builtins.ValueError"
SYM = "pkg.mod.f"


def _delta(pred, did="d1"):
    return {"id": did, "symbol": SYM, "predicate": {"type": "expr", "param": "x", "expr": pred},
            "expected": {"kind": "raises", "exc_type": EXC}}


def _guard(cond, line=1):
    return {"kind": "unsupported_entry_guard", "side": "post", "caller_qualified_name": SYM,
            "raised_exception": EXC, "condition_source": cond, "line_number": line}


# ----------------------------------------------------------------------------- design review's F-C1, verbatim shape
def test_f_c1_one_delta_must_not_cover_a_second_guard_of_the_same_exception_type():
    guards = [_guard("x < 0", 3), _guard("secret_backdoor(x)", 5)]
    deltas = [{"id": "d1", "symbol": SYM, "predicate": "x < 0", "expected": {"kind": "raises", "exc_type": EXC}}]
    obs = {"delta_observations": {"d1": {"raised_examples": [{"args": [i], "inject": False} for i in range(-12, 0)],
                                         "raised_expected_count": 12, "nonmatching_agree_count": 12}}}
    cov = [guard_coverage(g, obs, deltas, SYM, params=("x",)) for g in guards]
    assert [c.covered for c in cov] == [True, False], [c.reason for c in cov]
    assert "not decidable" in cov[1].reason
    # without the parameter names nothing can be attributed: fail closed, never 'covered by exception type'
    assert not any(guard_coverage(g, obs, deltas, SYM).covered for g in guards)


# ----------------------------------------------------------------------------- execution-based oracle
PROGRAMS = {
    "two_guards_one_outside_delta": ("def f(x):\n    if x < 0:\n        raise ValueError('neg')\n"
                                     "    if x == 4242:\n        raise ValueError('backdoor')\n    return x\n", "x < 0"),
    "guard_inside_delta": ("def f(x):\n    if x < -10:\n        raise ValueError('very neg')\n    return x\n", "x < 0"),
    "guard_wider_than_delta": ("def f(x):\n    if x < 5:\n        raise ValueError('small')\n    return x\n", "x < 0"),
    "odd_guard": ("def f(x):\n    if x % 2 == 1:\n        raise ValueError('odd')\n    return x\n", "x < 0"),
    "shadowed_inner_guard": ("def f(x):\n    if x < 0:\n        raise ValueError('neg')\n"
                             "    if x < -5:\n        raise ValueError('very neg')\n    return x\n", "x < 0"),
    "undecidable_helper": ("def secret(x):\n    return x == 99\n\n\ndef f(x):\n    if x < 0:\n        raise ValueError('neg')\n"
                           "    if secret(x):\n        raise ValueError('s')\n    return x\n", "x < 0"),
}
GRID = list(range(-40, 120)) + [4242]


def _run_program(src):
    g = {}
    exec(compile(src, "<fixture>", "exec"), g)
    f = g["f"]
    raised = {}  # x -> raising source line (traceback attribution)
    for x in GRID:
        try:
            f(x)
        except ValueError as e:
            tb = [fr for fr in traceback.extract_tb(e.__traceback__) if fr.filename == "<fixture>"][-1]
            raised[x] = tb.lineno
    return raised


def _guards_of(src):
    """(line, condition source) of every `if COND:` whose body is a single raise (read from the text)."""
    import re

    out = []
    for i, line in enumerate(src.splitlines(), 1):
        m = re.match(r"\s+if (.+):\s*$", line)
        if m and "raise" in src.splitlines()[i]:
            out.append((i, m.group(1)))
    return out


@pytest.mark.parametrize("name", sorted(PROGRAMS))
def test_guard_coverage_agrees_with_the_execution_oracle(name):
    src, pred = PROGRAMS[name]
    raised = _run_program(src)
    in_p = lambda x: bool(eval(pred, {"x": x}))  # noqa: S307 - test fixture, own predicate
    examples = [{"args": [x], "inject": False} for x in GRID if x in raised and in_p(x)]
    obs = {"delta_observations": {"d1": {"raised_examples": examples, "raised_expected_count": len(examples),
                                         "nonmatching_agree_count": 10, "truncated": False}}}
    for line, cond in _guards_of(src):
        outside = [x for x, ln in raised.items() if ln == line + 1 and not in_p(x)]
        exercised = sum(1 for x in GRID if in_p(x) and _py_true(cond, x, src))
        oracle = not outside and exercised >= 5
        got = guard_coverage(_guard(cond, line), obs, [_delta(pred)], SYM, params=("x",))
        assert got.covered == oracle, (name, cond, "oracle", oracle, "outside", outside[:3], "exercised", exercised, got.reason)


def _py_true(cond, x, src):
    g = {}
    exec(compile(src, "<fixture>", "exec"), g)  # helpers like secret() live in the fixture module
    try:
        return bool(eval(cond, {**g, "x": x}))
    except Exception:  # noqa: BLE001
        return False


# ----------------------------------------------------------------------------- negatives
def test_renamed_parameter_in_the_delta_does_not_cover():
    d = _delta("x < 0")  # the callable's parameter is `n`: the delta talks about something that does not exist
    obs = {"delta_observations": {"d1": {"raised_examples": [{"args": [-i]} for i in range(1, 9)],
                                         "raised_expected_count": 8, "nonmatching_agree_count": 9}}}
    r = guard_coverage(_guard("n < 0"), obs, [d], SYM, params=("n",))
    assert not r.covered and "not parameters" in r.reason


def test_guard_without_condition_source_is_never_covered():
    g = {k: v for k, v in _guard("x < 0").items() if k != "condition_source"}
    obs = {"delta_observations": {"d1": {"raised_examples": [{"args": [-i]} for i in range(1, 9)],
                                         "raised_expected_count": 8, "nonmatching_agree_count": 9}}}
    assert not guard_coverage(g, obs, [_delta("x < 0")], SYM, params=("x",)).covered


def test_typed_predicate_delta_identifies_the_guard_too():
    d = {"id": "d1", "symbol": SYM, "predicate": {"type": "typed", "param": "x", "class": "int_neg"},
         "expected": {"kind": "raises", "exc_type": EXC}}
    obs = {"delta_observations": {"d1": {"raised_examples": [{"args": [-i]} for i in range(1, 9)],
                                         "raised_expected_count": 8, "nonmatching_agree_count": 9}}}
    assert guard_coverage(_guard("x < 0"), obs, [d], SYM, params=("x",)).covered
    assert not guard_coverage(_guard("x == 4242"), obs, [d], SYM, params=("x",)).covered


# ----------------------------------------------------------------------------- removed guards
def _removed_obs(n=8, agree=9, pre_exc=EXC, post_kind="ret"):
    ex = [{"args": [-i], "pre": {"k": "exc", "t": pre_exc}, "post": {"k": post_kind}} for i in range(1, n + 1)]
    return {"delta_observations": {"d1": {"matched_examples": ex, "matched_count": n, "nonmatching_agree_count": agree}}}


RD = {"id": "d1", "symbol": SYM, "predicate": {"type": "expr", "param": "x", "expr": "x < 0"},
      "expected": {"kind": "returns", "value_repr": "None"}}


def test_removed_guard_is_not_covered_without_a_delta_or_observations():
    assert not removed_guard_coverage("x < 0", EXC, _removed_obs(), [], SYM, params=("x",)).covered
    assert not removed_guard_coverage("x < 0", EXC, None, [RD], SYM, params=("x",)).covered
    assert not removed_guard_coverage("x < 0", None, _removed_obs(), [RD], SYM, params=("x",)).covered


def test_removed_guard_covered_only_by_a_delta_that_explains_it():
    assert removed_guard_coverage("x < 0", EXC, _removed_obs(), [RD], SYM, params=("x",)).covered
    # the removed guard was a DIFFERENT one than the delta's region (x == 4242 vs x < 0)
    assert not removed_guard_coverage("x == 4242", EXC, _removed_obs(), [RD], SYM, params=("x",)).covered
    # pre did not raise that exception on the observed inputs: the delta explains something else
    assert not removed_guard_coverage("x < 0", EXC, _removed_obs(pre_exc="builtins.KeyError"), [RD], SYM, params=("x",)).covered
    # too few observed inputs
    assert not removed_guard_coverage("x < 0", EXC, _removed_obs(n=3), [RD], SYM, params=("x",)).covered
    # an undecidable removed condition is never covered
    assert not removed_guard_coverage("secret(x)", EXC, _removed_obs(), [RD], SYM, params=("x",)).covered
