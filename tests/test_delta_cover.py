# SPDX-License-Identifier: Apache-2.0
"""Guard coverage: covered only by an exact, observed, machine-checkable delta; every miss keeps the guard blocking."""
from hlith.delta_cover import guard_coverage

SYM = "diff_cover.util.to_unescaped_filename"
GUARD = {"kind": "unsupported_entry_guard", "side": "post", "raised_exception": "builtins.ValueError",
         "condition_source": "'\\\\0' in filename"}
P = ("filename",)  # guard identity (F-C1): coverage needs the callable's parameter names
DELTA = {"id": "nul", "symbol": SYM, "predicate": {"type": "expr", "param": "filename", "expr": "'\\\\0' in filename"},
         "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}


def _obs(trig=6, agree=40, inject_extra=0, truncated=False):
    ex = [{"args": [f"a\\0{i}"], "post": {"raised": "builtins.ValueError"}} for i in range(trig)]
    ex += [{"args": ["x"], "inject": {"f": "e"}} for _ in range(inject_extra)]
    return {"delta_observations": {"nul": {"raised_expected_count": trig + inject_extra, "raised_examples": ex,
                                           "nonmatching_agree_count": agree, "truncated": truncated}}}


def test_exact_observed_delta_covers_the_guard():
    r = guard_coverage(GUARD, _obs(), [DELTA], SYM, params=P)
    assert r.covered and r.delta_id == "nul" and "conditional on deltas-confirmed" in r.evidence


def test_wrong_exception_type_does_not_cover():
    g = dict(GUARD, raised_exception="builtins.TypeError")
    assert not guard_coverage(g, _obs(), [DELTA], SYM, params=P).covered


def test_too_few_triggering_or_agreeing_inputs_do_not_cover():
    assert not guard_coverage(GUARD, _obs(trig=4), [DELTA], SYM, params=P).covered
    assert not guard_coverage(GUARD, _obs(agree=4), [DELTA], SYM, params=P).covered


def test_injected_calls_do_not_count_as_triggers():
    r = guard_coverage(GUARD, _obs(trig=3, inject_extra=10), [DELTA], SYM, params=P)
    assert not r.covered and "plain triggering" in r.reason


def test_advisory_delta_and_unresolved_exception_and_pre_side_do_not_cover():
    adv = {k: v for k, v in DELTA.items() if k != "predicate"}
    assert not guard_coverage(GUARD, _obs(), [adv], SYM, params=P).covered
    assert not guard_coverage(dict(GUARD, raised_exception=None), _obs(), [DELTA], SYM, params=P).covered
    assert not guard_coverage(dict(GUARD, side="pre"), _obs(), [DELTA], SYM, params=P).covered


def test_delta_for_another_symbol_or_no_observations_does_not_cover():
    assert not guard_coverage(GUARD, _obs(), [dict(DELTA, symbol="x.y")], SYM, params=P).covered
    assert not guard_coverage(GUARD, None, [DELTA], SYM, params=P).covered


def test_undecidable_delta_predicate_on_observed_example_does_not_cover():
    g = {"kind": "unsupported_entry_guard", "side": "post", "raised_exception": "builtins.ValueError",
         "condition_source": "isinstance(s, str) and len(s) == 3"}
    d = {"id": "d1", "symbol": "m.f",
         "predicate": {"type": "expr", "param": "s", "expr": "s.isascii()"},
         "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}
    obs = {"delta_observations": {"d1": {"raised_expected_count": 6,
                                         "raised_examples": [{"args": ["foo"]} for _ in range(6)],
                                         "nonmatching_agree_count": 40}}}
    r = guard_coverage(g, obs, [d], "m.f", params=("s",))
    assert not r.covered and "decidable" in r.reason, r


def test_partial_or_undecided_guard_vs_predicate_check_does_not_cover(monkeypatch):
    g = {"kind": "unsupported_entry_guard", "side": "post", "raised_exception": "builtins.ValueError",
         "condition_source": "isinstance(s, str)"}
    d = {"id": "d1", "symbol": "m.f",
         "predicate": {"type": "expr", "param": "s", "expr": "isinstance(s, str) and (len(s) == 3 or s.isascii())"},
         "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}
    obs = {"delta_observations": {"d1": {"raised_expected_count": 6,
                                         "raised_examples": [{"args": ["foo"]} for _ in range(6)],
                                         "nonmatching_agree_count": 40}}}
    r = guard_coverage(g, obs, [d], "m.f", params=("s",))
    assert not r.covered, r

    from hlith import drive_inputs as di

    g2 = {"kind": "unsupported_entry_guard", "side": "post", "raised_exception": "builtins.ValueError",
          "condition_source": "x < 0"}
    d2 = {"id": "d2", "symbol": "m.f", "predicate": {"type": "expr", "param": "x", "expr": "not (x >= 0)"},
          "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}
    obs2 = {"delta_observations": {"d2": {"raised_expected_count": 6,
                                          "raised_examples": [{"args": [-1]} for _ in range(6)],
                                          "nonmatching_agree_count": 40}}}
    assert guard_coverage(g2, obs2, [d2], "m.f", params=("x",)).covered
    monkeypatch.setattr(di, "candidates_detailed", lambda *a, **k: ([], {0: "true: solver timeout"}))
    r2 = guard_coverage(g2, obs2, [d2], "m.f", params=("x",))
    assert not r2.covered and "decided" in r2.reason, r2


def test_symbolic_sequence_k_bound_beyond_k_does_not_cover():
    # Counterexample outside K=4: [1, 0, 0, 0, 0] satisfies guard condition (len==5, x[0]==1) but not `7 in x`.
    g = {"kind": "unsupported_entry_guard", "side": "post", "raised_exception": "builtins.ValueError",
         "condition_source": "isinstance(x, list) and len(x) == 5 and x[0] == 1"}
    d = {"id": "d1", "symbol": "m.f",
         "predicate": {"type": "expr", "param": "x", "expr": "isinstance(x, list) and len(x) == 5 and x[0] == 1 and 7 in x"},
         "expected": {"kind": "raises", "exc_type": "builtins.ValueError"}}
    obs = {"delta_observations": {"d1": {"raised_expected_count": 6,
                                         "raised_examples": [{"args": [[1, 0, 0, 0, 7]]} for _ in range(6)],
                                         "nonmatching_agree_count": 40}}}
    r = guard_coverage(g, obs, [d], "m.f", params=("x",))
    assert not r.covered and "decided" in r.reason, r
