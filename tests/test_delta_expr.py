"""expected returns_expr: the closed grammar for COMPUTED intended changes (design review ruling 2026-11-13, maintainer case:
super_len(str) == len(o.encode('utf-8')) for every str). review owns grammar + interpreter (hlith.expected_expr),
validate_delta, schema and the pin-coverage guard; review's matcher calls evaluate_expected_expr in the confined evaluator.
Red-first: adversarial expressions are rejected at validation or fail closed at evaluation (never a match)."""
import json

import pytest

from hlith import expected_expr as xe
from hlith.runtime import delta_set_sha256, validate_delta, validate_deltas

SUPER_LEN = "len(o.encode('utf-8'))"


def _delta(expr, *, pred=None, did="computed"):
    return {"id": did, "symbol": "requests.utils.super_len", "kind": "behavior",
            "claim": "a str's length is its UTF-8 byte count", "input_domain": "o is a str", "pre": "len(o)",
            "post": "len(o.encode('utf-8'))",
            "predicate": pred or {"type": "expr", "param": "o", "expr": "isinstance(o, str)"},
            "expected": {"kind": "returns_expr", "expr": expr}}


def _ev(expr, **b):
    return xe.evaluate_expected_expr(expr, b)


# --- the positive behaviour: the maintainer case is declarable and evaluates per input ---

def test_recorded_case_validates_and_evaluates_per_input():
    d = validate_delta(_delta(SUPER_LEN))
    assert d["expected"] == {"kind": "returns_expr", "expr": SUPER_LEN}
    for s, n in (("", 0), ("abc", 3), ("é", 2), ("€", 3), ("𝄞", 4), ("á", 3)):
        assert _ev(SUPER_LEN, o=s) == (True, n)
    ok, v = _ev(SUPER_LEN, o="é")
    assert xe.value_matches(v, 2) and not xe.value_matches(v, 1)  # a genuinely different post value
    assert not xe.value_matches(1, True) and not xe.value_matches(True, 1) and not xe.value_matches(2, 2.0)
    assert xe.value_matches((1, [b"a", {"k": None}]), (1, [b"a", {"k": None}]))
    assert not xe.value_matches((1, 2), [1, 2])


def test_names_are_all_bound_call_parameters():
    assert xe.validate_expected_expr("a if b is None else len(c)", ["a", "b", "c"]) == (True, "")
    ok, why = xe.validate_expected_expr("len(x)", ["o"])
    assert not ok and "not a parameter" in why
    assert xe.validate_expected_expr("len(x)", None) == (True, "")  # manifest time: bound later
    ok, why = _ev("len(x)", o="a")  # unbound at evaluation: fails closed
    assert not ok and "not bound" in why or "not a parameter" in why
    d = validate_delta(_delta("a + b", pred={"type": "literal_inputs", "inputs": [{"args": [1, 2], "kwargs": {}}]}))
    assert d["expected"]["expr"] == "a + b"


@pytest.mark.parametrize("expr,b,want", [
    ("None if b is None else a", {"a": 1, "b": None}, None),
    ("o.strip().lower()", {"o": "  AbC "}, "abc"),
    ("o.upper().startswith('AB')", {"o": "abc"}, True),
    ("o.replace('a', 'b', 1)", {"o": "aaa"}, "baa"),
    ("o.encode('utf-8').decode('utf-8')", {"o": "é"}, "é"),
    ("o.casefold() == 'strasse'", {"o": "STRASSE"}, True),
    ("o[1:3] + o[0]", {"o": "abcd"}, "bca"),
    ("max(len(o), 3) * 2 - abs(-1) // 1 % 7", {"o": "ab"}, 5),
    ("min(len(o), 1)", {"o": ""}, 0),
    ("str(len(o)) + 'b'", {"o": "xyz"}, "3b"),
    ("int(o) + 1", {"o": "41"}, 42),
    ("bool(o) and not o.endswith(('x', 'y'))", {"o": "ab"}, True),
    ("(1, 2)", {"o": 0}, (1, 2)),
    ("o['k']", {"o": {"k": 5}}, 5),
    ("','.join(sorted(o.split(' ')))", {"o": "b a c"}, "a,b,c"),
    ("tuple(list(o))", {"o": "ab"}, ("a", "b")),
    ("o.lstrip('x').count('a') + o.rstrip('y').find('q')", {"o": "xaay"}, 1),
    ("o.lstrip('x').rstrip('y').count('a') + o.find('q')", {"o": "xaay"}, None),  # depth 7: rejected
    ("round(float(o), 1)", {"o": "2.25"}, 2.2),
    ("bytes(o) + b'!'", {"o": [104, 105]}, b"hi!"),
    ("o * 3", {"o": "ab"}, "ababab"),
])
def test_grammar_covers_the_allowlist(expr, b, want):
    if want is None and expr.startswith("o.lstrip('x').rstrip"):  # each chained method costs 2 levels (call+attr)
        assert "deeper" in xe.validate_expected_expr(expr, list(b))[1]
        return
    assert xe.validate_expected_expr(expr, list(b)) == (True, "")
    ok, got = xe.evaluate_expected_expr(expr, b)
    assert ok and xe.value_matches(got, want), (expr, got)


# --- red-first adversarial expressions: rejected by the closed grammar (and by validate_delta) ---

@pytest.mark.parametrize("expr", [
    "o.__class__",  # dunder escape
    "o.__class__.__mro__[1].__subclasses__()",
    "().__class__.__bases__[0]",
    "getattr(o, '__class__')",
    "'a' * 10 ** 9",  # ** is not in the grammar
    "'a' * 1000000000",  # repetition by a non-small literal
    "o * len(o)",  # repetition by a computed count
    "[c for c in o]",  # comprehension
    "(c for c in o)",  # generator
    "{c: 1 for c in o}",
    "(n := len(o))",  # walrus
    "(lambda: 1)()",
    "__import__('os')",
    "eval('1')",
    "open('/etc/passwd')",
    "print",
    "f'{o!r:>1000000000}'",  # f-string
    "o.format(1)",  # method not on the allowlist
    "o.encode(encoding='utf-8')",  # keyword arguments
    "o.encode('rot13')",  # codec not on the allowlist
    "o.encode('utf-8').decode('latin-1')",  # decode is utf-8 only
    "o.encode('utf-8', 'strict', 1)",
    "len(*o)",
    "o.upper",  # attribute outside a call
    "o.__len__()",
    "[o]",
    "{o}",
    "{'k': o}",
    "len(o) is 3",  # `is` only against None
    "~len(o)",
    "len(o) << 3",
    "len(" * 8 + "o" + ")" * 8,  # depth
    "+".join(["len(o)"] * 15),  # nodes
    "o" + " " * 500,  # length
    "o\n",
    "await o",
    "o if o else o.__dict__",
])
def test_adversarial_expressions_are_rejected(expr):
    ok, why = xe.validate_expected_expr(expr, ["o"])
    assert not ok and why, expr
    # SEAM CHANGE: L1's validate_delta checks serialization and size bounds only; the expression GRAMMAR is
    # rejected at L3, before the delta can reach any verdict. Same assertion, now where the check lives: the differential's
    # delta validation refuses the delta and names the expression (a refused delta is never checkable, so it covers nothing).
    from hlith import differential

    checkable, errors = differential._validate_deltas([_delta(expr)])
    assert not checkable and any("expected expr rejected" in e for e in errors), (expr, errors)
    ok, why = _ev(expr, o="a")
    assert not ok


# --- adversarial at evaluation: bounded, fail closed ((False, reason) = the delta does not cover the input) ---

class _Evil(str):
    def __str__(self):
        raise AssertionError("user code ran")

    def __len__(self):
        raise AssertionError("user code ran")


@pytest.mark.parametrize("expr,b", [
    ("('a' * 1024) * 1024", {"o": 0}),  # 1 MiB intermediate
    ("o * 1024", {"o": "a" * 1000}),
    ("o.replace('', 'xxxxxxxxxxxxxxxx')", {"o": "a" * 50_000}),
    ("'%1000000000d' % len(o)", {"o": "a"}),  # str % is never evaluated
    ("len(o) // 0", {"o": "a"}),
    ("int(o)", {"o": "9" * 5000}),
    ("o.encode('utf-8')", {"o": 5}),  # method on a non-str receiver
    ("len(o)", {"o": object()}),  # non-inert value never reaches a builtin
    ("str(o)", {"o": _Evil("x")}),  # str subclass: not inert, its __str__ never runs
    ("len(o)", {"o": _Evil("x")}),
    ("o == 1", {"o": type("Q", (), {"__eq__": lambda s, x: True})()}),
    ("o + 'x'", {"o": 1}),
    ("o < 'a'", {"o": 1}),
    ("o[5]", {"o": "a"}),
    ("bytes(o)", {"o": 10 ** 9}),
    ("','.join(o)", {"o": ["a" * 40_000, "b" * 40_000]}),
])
def test_evaluation_is_bounded_and_fails_closed(expr, b):
    assert xe.validate_expected_expr(expr, list(b))[0], expr
    ok, why = xe.evaluate_expected_expr(expr, b)
    assert not ok and isinstance(why, str), (expr, why)


def test_step_budget_bounds_evaluation():
    assert _ev("len(o) + len(o) + len(o)", o="ab") == (True, 6)
    ok, why = xe.evaluate_expected_expr("len(o) + len(o) + len(o)", {"o": "ab"}, max_steps=3)
    assert not ok and "step" in why


def test_inert_values_and_reprs():
    assert xe.inert_from_repr("'é'") == (True, "é") and xe.inert_from_repr("(1, b'x', None)") == (True, (1, b"x", None))
    for bad in ("<object at 0x1>", "__import__('os')", "{1, 2}", "1j", "x" * 70_000, "'abc"):
        assert not xe.inert_from_repr(bad)[0], bad
    weird = type("W", (int,), {"__eq__": lambda s, x: True})(3)
    assert not xe.is_inert(weird) and not xe.value_matches(3, weird) and not xe.value_matches([1, weird], [1, 3])


# --- validate_delta: shape, exclusivity, hashing ---

def test_validate_delta_shape_rules():
    with pytest.raises(ValueError):
        validate_delta({**_delta(SUPER_LEN), "expected": {"kind": "returns_expr", "expr": SUPER_LEN, "value_repr": "1"}})
    with pytest.raises(ValueError):
        validate_delta({**_delta(SUPER_LEN), "expected": {"kind": "returns", "expr": SUPER_LEN}})  # returns: value_repr only
    with pytest.raises(ValueError):
        validate_delta({**_delta(SUPER_LEN), "expected": {"kind": "returns_expr"}})
    assert validate_delta(_delta("len(o)"))["expected"] == {"kind": "returns_expr", "expr": "len(o)"}


def test_delta_hash_and_approval_cover_the_expr_text():
    a = validate_deltas([_delta(SUPER_LEN)])
    b = validate_deltas([_delta("len(o.encode('utf-16'))")])
    assert delta_set_sha256(a) != delta_set_sha256(b)
    assert SUPER_LEN in json.dumps(a)


def test_artifact_schema_closes_returns_expr():
    """The artifact's intended_delta.expected gains the closed returns_expr variant; returns keeps value_repr only."""
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent))
    from test_feedback import SCHEMA, schema_errors

    root = json.loads(SCHEMA.read_text())
    sch = root["$defs"]["intended_delta"]
    d = validate_delta(_delta(SUPER_LEN))
    assert schema_errors(d, sch, root) == []
    for bad in ({"kind": "returns_expr", "expr": SUPER_LEN, "value_repr": "1"}, {"kind": "returns_expr"},
                {"kind": "returns", "expr": SUPER_LEN}, {"kind": "returns_expr", "expr": ""},
                {"kind": "returns_expr", "expr": "a\nb"}, {"kind": "returns_expr", "expr": "x" * 401}):
        assert schema_errors({**d, "expected": bad}, sch, root), bad


# --- review Task 3: a str SUBCLASS as expression text / parameter name / repr runs user code in the supervisor ---

class _Hooked(str):
    calls: list = []

    def __len__(self):
        _Hooked.calls.append("__len__")
        return super().__len__()

    def __iter__(self):
        _Hooked.calls.append("__iter__")
        return super().__iter__()


def test_non_exact_str_inputs_are_refused_before_any_method_runs():
    _Hooked.calls = []
    assert not xe.validate_expected_expr(_Hooked("len(o)"), ["o"])[0]
    assert not xe.evaluate_expected_expr(_Hooked("len(o)"), {"o": "a"})[0]
    assert not xe.validate_expected_expr("len(o)", [_Hooked("o")])[0]
    assert not xe.evaluate_expected_expr("len(o)", {_Hooked("o"): "a"})[0]
    assert not xe.inert_from_repr(_Hooked("1"))[0]
    assert _Hooked.calls == [], _Hooked.calls


def test_delta_covers_pin_refuses_a_hooked_expr(tmp_path):
    """review's minimal case on the supervisor path: a returns_expr whose expr is a str subclass never covers a pin
    and no hook of it runs."""
    from hlith import feedback as fb
    from hlith import obligation

    # the operator wires L3's probe helpers into L5 at startup (feedback.register_probe_bridge); a bare unit test must too,
    # otherwise L5 has no matcher and refuses every pin (that is why this returned False)
    fb.register_probe_bridge(**obligation.probe_bridge())
    pin = fb.pin_regression_counterexample("r", "pkg.m.f", [], {"x": 0}, expected={"kind": "return", "repr": "1"},
                                           observed={"kind": "return", "repr": "0"})
    good = {"id": "d", "symbol": "pkg.m.f", "predicate": {"type": "literal_inputs", "inputs": [{"args": [], "kwargs": {"x": 0}}]},
            "expected": {"kind": "returns_expr", "expr": "x"}}
    assert fb.delta_covers_pin(good, pin, ["x"])  # the exact-str expression covers it
    _Hooked.calls = []
    evil = {**good, "expected": {"kind": "returns_expr", "expr": _Hooked("x")}}
    assert not fb.delta_covers_pin(evil, pin, ["x"])
    assert _Hooked.calls == [], _Hooked.calls


def test_validate_delta_touches_no_subclass_hook():
    """review: validate_delta ran a str subclass's __len__/__iter__ in _check_text before refusing it. Every text, key,
    container and enum value is type-checked EXACTLY before any method of it runs; refusal, no hook call."""
    class D(dict):
        def __iter__(self):
            _Hooked.calls.append("dict.__iter__")
            return super().__iter__()

    base = _delta(SUPER_LEN)
    cases = [{**base, "expected": {"kind": "returns_expr", "expr": _Hooked("len(o)")}},
             {**base, "id": _Hooked("computed")}, {**base, "kind": _Hooked("behavior")},
             {**base, "expected": {"kind": _Hooked("returns_expr"), "expr": "len(o)"}},
             {**base, "predicate": {"type": "typed", "param": "o", "class": _Hooked("none")}},
             {**base, "predicate": {"type": _Hooked("expr"), "param": "o", "expr": "x"}},
             {**base, "predicate": {"type": "literal_inputs", "inputs": [{"args": [_Hooked("a")], "kwargs": {}}]}},
             {**base, "predicate": {"type": "literal_inputs", "inputs": [{"args": [], "kwargs": {_Hooked("k"): 1}}]}},
             {**base, "expected": D(kind="returns_expr", expr="len(o)")}, D(base)]
    for c in cases:
        _Hooked.calls = []
        with pytest.raises(ValueError):
            validate_delta(c)
        assert _Hooked.calls == [], (c, _Hooked.calls)
    assert validate_delta(base)["expected"]["expr"] == SUPER_LEN  # exact types still validate
