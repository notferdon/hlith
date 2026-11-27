# SPDX-License-Identifier: Apache-2.0
"""O3 regression (review O3v2-A on 08d36ea): a guard that sits AFTER an early return must be attributed to the delta
predicate together with the dominating prefix, not path-insensitively. The prefix may only narrow where the guard
raises; it may never launder a raise outside the declared delta."""
import ast
import textwrap

from hlith.delta_cover import dominating_conditions, guard_coverage

SYM = "diff_cover.util.to_unescaped_filename"
SRC = textwrap.dedent('''
    def to_unescaped_filename(filename: str) -> str:
        if not (filename.startswith('"') and filename.endswith('"')):
            return filename

        if "\\\\0" in filename:
            raise ValueError("NUL escape in a quoted filename")
        return filename[1:-1]
''')
GUARD_LINE = 6
COND = '"\\\\0" in filename'
GUARD = {"kind": "unsupported_entry_guard", "side": "post", "raised_exception": "builtins.ValueError", "condition_source": COND}
PRED = "isinstance(filename, str) and filename.startswith('\"') and filename.endswith('\"') and '\\\\0' in filename"
DELTA = {"id": "nul-escape-rejected", "symbol": SYM, "predicate": {"type": "expr", "param": "filename", "expr": PRED},
         "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}
P = ("filename",)


def _obs(n=8, agree=40):
    ex = [{"args": ['"a\\\\0' + str(i) + '"'], "post": {"raised": "builtins.ValueError"}} for i in range(n)]
    return {"delta_observations": {DELTA["id"]: {"raised_expected_count": n, "raised_examples": ex, "nonmatching_agree_count": agree}}}


def test_dominating_conditions_of_an_early_return_are_negated_and_conjoined():
    conds = dominating_conditions(SRC, GUARD_LINE)
    assert len(conds) == 1
    t = ast.parse(conds[0], mode="eval").body
    assert isinstance(t, ast.UnaryOp) and isinstance(t.op, ast.Not)  # not (the early-return test)


def test_regression_guard_after_early_return_is_covered_by_the_complete_delta():
    # path-insensitive (no prefix): the old answer, refused because '\0' in an UNQUOTED filename "raises outside the predicate"
    r0 = guard_coverage(GUARD, _obs(), [DELTA], SYM, params=P)
    assert not r0.covered and "outside the delta predicate" in r0.reason
    g = dict(GUARD, dominating_conditions=dominating_conditions(SRC, GUARD_LINE))
    r = guard_coverage(g, _obs(), [DELTA], SYM, params=P)
    assert r.covered, r.reason


def test_prefix_does_not_launder_a_raise_outside_the_declared_delta():
    # the guard also fires for quoted names that do NOT end with a quote? no: predicate is narrower than the guard's real
    # domain (needs a leading 'q'), so a raise exists outside it even with the prefix: refused
    narrow = dict(DELTA, predicate={"type": "expr", "param": "filename", "expr": PRED + " and filename.startswith('\"q')"})
    g = dict(GUARD, dominating_conditions=dominating_conditions(SRC, GUARD_LINE))
    ex = [{"args": ['"q\\\\0' + str(i) + '"']} for i in range(8)]
    obs = {"delta_observations": {narrow["id"]: {"raised_expected_count": 8, "raised_examples": ex, "nonmatching_agree_count": 40}}}
    r = guard_coverage(g, obs, [narrow], SYM, params=P)
    assert not r.covered and "outside the delta predicate" in r.reason


def test_non_terminal_conditional_and_loop_bodies_do_not_dominate():
    src = textwrap.dedent('''
        def f(x):
            if x == 1:
                y = 2
            for i in x:
                if i:
                    return i
            if "\\\\0" in x:
                raise ValueError("n")
    ''')
    assert dominating_conditions(src, 8) == []  # a conditional that does not always leave, and a loop, add nothing


def test_guard_nested_in_a_branch_inherits_the_branch_condition_and_else_negates_it():
    src = textwrap.dedent('''
        def f(x):
            if x.startswith("a"):
                if "\\\\0" in x:
                    raise ValueError("n")
            else:
                if "\\\\0" in x:
                    raise ValueError("m")
    ''')
    a = dominating_conditions(src, 4)
    b = dominating_conditions(src, 7)
    assert a == ["x.startswith('a')"] and b == ["not x.startswith('a')"]


def test_unknown_line_or_unparsable_source_gives_no_prefix_never_a_guess():
    assert dominating_conditions(SRC, 999) == []
    assert dominating_conditions("def (:", 1) == []


def test_prefix_dropped_when_its_name_is_rebound_or_mutated_before_the_guard():
    rebound = textwrap.dedent('''
        def f(x):
            if not x.startswith("q"):
                return x
            x = x.replace("q", "")
            if "\\\\0" in x:
                raise ValueError("n")
    ''')
    assert dominating_conditions(rebound, 6) == []  # x no longer is what the early return tested
    mutated = textwrap.dedent('''
        def f(x):
            if not x:
                return x
            x.clear()
            if "\\\\0" in x:
                raise ValueError("n")
    ''')
    assert dominating_conditions(mutated, 6) == []


def test_a_prefix_the_evaluator_cannot_read_is_ignored_so_coverage_refuses_more_not_less():
    g = dict(GUARD, dominating_conditions=["some_global_flag(filename)"])
    r = guard_coverage(g, _obs(), [DELTA], SYM, params=P)
    assert not r.covered and "outside the delta predicate" in r.reason
