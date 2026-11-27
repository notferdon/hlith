# SPDX-License-Identifier: Apache-2.0
"""Bounded, annotation-shaped inputs stay typed across the isolated driver boundary."""

from datetime import timedelta

from hlith import differential
from hlith import drive_inputs as D
from hlith.expected_expr import inert_from_repr, value_matches
import pytest


@pytest.mark.parametrize("max_per_condition", [1, 4])
def test_nested_builtin_generic_shape_drives_real_python_condition(max_per_condition):
    source = (
        "def f(pairs: list[tuple[str, str]]):\n"
        "    if len(pairs) == 1 and pairs[0][0] == 'a':\n"
        "        return True\n"
        "    return False\n"
    )
    fn = D.ast.parse(source).body[0]
    params, why = D.candidates_detailed(
        [("pairs", "list[tuple[str, str]]")],
        ["len(pairs) == 1 and pairs[0][0] == 'a'"],
        want="true",
        timeout_ms=100,
        max_per_condition=max_per_condition,
        fn_ast=fn,
        target_lineno=2,
    )
    assert params, why
    assert any(
        (restored := differential._materialise_desc(candidate.params["pairs"])) is not None
        and candidate.exact is False
        and "bounded annotation-shape seed (not exhaustive)" in candidate.origin
        and type(restored) is list
        and len(restored) <= D.K_MAX
        and all(type(pair) is tuple and len(pair) == 2 and all(type(x) is str for x in pair)
                for pair in restored)
        and D._holds(D._parse_expr("len(pairs) == 1 and pairs[0][0] == 'a'", None), True, [],
                     {"pairs": restored}, {}) is True
        for candidate in params
    )


def test_fixed_tuple_generic_shape_drives_real_python_condition():
    source = (
        "def f(pair: tuple[str, str]):\n"
        "    if pair[0] == 'a' and pair[1] == 'b':\n"
        "        return True\n"
        "    return False\n"
    )
    fn = D.ast.parse(source).body[0]
    params, why = D.candidates_detailed(
        [("pair", "tuple[str, str]")], ["pair[0] == 'a' and pair[1] == 'b'"],
        want="true", timeout_ms=100, max_per_condition=1, fn_ast=fn, target_lineno=2,
    )
    assert params, why
    restored = differential._materialise_desc(params[0].params["pair"])
    assert type(restored) is tuple and restored == ("a", "b")
    assert params[0].exact is False
    assert "bounded annotation-shape seed (not exhaustive)" in params[0].origin


def test_unused_nested_generic_parameter_does_not_block_other_candidates():
    source = (
        "def f(n: int, pairs: list[tuple[str, str]]):\n"
        "    if n == 1:\n"
        "        return True\n"
        "    return False\n"
    )
    fn = D.ast.parse(source).body[0]
    params, why = D.candidates_detailed(
        [("n", "int"), ("pairs", "list[tuple[str, str]]")], ["n == 1"],
        want="true", timeout_ms=100, max_per_condition=2, fn_ast=fn, target_lineno=2,
    )
    assert params, why
    assert all("pairs" not in candidate.params for candidate in params)


@pytest.mark.parametrize("annotation", ["list[Custom]", "list[tuple[str, Custom]]"])
def test_unknown_nested_generic_leaf_stays_not_derived(annotation):
    source = f"def f(items: {annotation}):\n    if len(items) == 1:\n        return True\n    return False\n"
    fn = D.ast.parse(source).body[0]
    params, why = D.candidates_detailed(
        [("items", annotation)], ["len(items) == 1"], want="true",
        timeout_ms=100, max_per_condition=4, fn_ast=fn, target_lineno=2,
    )
    assert not params
    assert "unsupported" in str(why).lower(), why


def test_nested_shape_seed_pool_is_deterministic_and_bounded():
    shape, error = D._annotation_shape("list[tuple[str, str]]")
    assert error is None and shape == ("list", ("tuple", ("str",), ("str",)))
    first = D._shape_seed_values(shape, [0, 1, -1], ["a", "b"])
    second = D._shape_seed_values(shape, [0, 1, -1], ["a", "b"])
    assert first == second
    assert len(first) <= D._MAX_SHAPE_SEEDS
    assert all(D._matches_shape(value, shape) for value in first)
    assert all(len(value) <= D._MAX_SHAPE_LIST_LEN for value in first)
    assert D._annotation_shape("list[Custom]")[0] is None
    assert D._annotation_shape("list[Custom]")[1]


@pytest.mark.parametrize("annotation", ["list[str] | None", "Optional[list[str]]", "Union[list[str], None]"])
def test_optional_nested_generic_preserves_none_and_declared_container_shape(annotation):
    shape, error = D._annotation_shape(annotation)
    info_shape, info_error, optional = D._annotation_shape_info(annotation)
    params = D._build_params({"items": (annotation, None)}, [], {})

    assert error is None and info_error is None
    assert shape == info_shape == ("list", ("str",))
    assert optional
    assert params["items"].shape == shape and params["items"].optional
    assert D._matches_shape(None, shape, optional=True)
    assert not D._matches_shape(None, shape)


def test_differential_strategy_preserves_fixed_nested_tuple_element_types():
    from hypothesis import find, settings, strategies as st

    strategy, error = differential._strategy(st, "list[tuple[str, str]]", None, False, [])
    assert strategy is not None, error
    sample = find(strategy, lambda value: bool(value), settings=settings(max_examples=20, database=None))
    assert type(sample) is list and sample
    assert all(type(pair) is tuple and len(pair) == 2 and all(type(item) is str for item in pair)
               for pair in sample)


def test_differential_strategy_uses_bounded_concrete_elements_for_iterable_any():
    from hypothesis import find, settings, strategies as st

    strategy, error = differential._strategy(st, "Iterable[Any]", None, False, ["a", "b", "c"])
    assert strategy is not None, error
    sample = find(strategy, lambda value: type(value) is list and len(value) >= 3,
                  settings=settings(max_examples=200, database=None))
    assert type(sample) is list and 3 <= len(sample) <= 5
    assert all(type(item) in (str, int, type(None), bool, float, bytes) for item in sample)


def test_differential_strategy_keeps_unknown_iterable_elements_not_derived():
    from hypothesis import strategies as st

    strategy, error = differential._strategy(st, "Iterable[Custom]", None, False, [])
    assert strategy is None
    assert "no derivable strategy" in error


def test_nested_tuple_values_round_trip_through_differential_descriptor():
    value = [("a", "b"), ("A", "B")]
    params = {"char_list": value}
    json_form = D._json_form(params, params, {"char_list": D._P("char_list", "list")})
    assert json_form == {"char_list": [{"__tuple__": ["a", "b"]}, {"__tuple__": ["A", "B"]}]}
    restored = differential._materialise_desc(json_form["char_list"])
    assert type(restored) is list
    assert all(type(item) is tuple for item in restored)
    assert restored == value

    pair = ("a", "b")
    pair_json = D._json_form({"pair": pair}, {"pair": pair}, {"pair": D._P("pair", "tuple", shape=("tuple", ("str",), ("str",)))})
    assert differential._materialise_desc(pair_json["pair"]) == pair
    assert type(differential._materialise_desc(pair_json["pair"])) is tuple


@pytest.mark.parametrize(
    ("attribute", "threshold", "around"),
    [("seconds", 60, (59, 60, 61)), ("days", 0, (-1, 0, 1)),
     ("microseconds", 1, (0, 1, 2))],
)
def test_timedelta_attribute_boundaries_are_deterministic_and_rechecked(attribute, threshold, around):
    source = (
        "def f(delta: datetime.timedelta):\n"
        f"    if delta.{attribute} < {threshold}:\n"
        "        return True\n"
        "    return False\n"
    )
    fn = D.ast.parse(source).body[0]
    seeds = differential._condition_tuple_seeds(fn, None)
    calls = differential._seed_calls(
        [("delta", "datetime.timedelta", None, False)], ["kw"], [], 32,
        cond_seeds=seeds,
    )
    values = [kwargs["delta"] for _, kwargs in calls if "delta" in kwargs]
    field = {"seconds": "seconds", "days": "days", "microseconds": "microseconds"}[attribute]
    component_values = {getattr(value, field) for value in values if type(value) is timedelta}

    assert values
    assert set(around) <= component_values
    assert timedelta(0) in values
    assert timedelta(days=-1) in values
    assert timedelta.min in values and timedelta.max in values
    assert len(values) <= 32
    assert seeds == differential._condition_tuple_seeds(fn, None)
    condition = D._parse_expr(f"delta.{attribute} < {threshold}", None)
    for value in values:
        assert type(value) is timedelta
        assert D._holds(condition, True, [], {"delta": value}, {}) is (getattr(value, field) < threshold)


def test_custom_timedelta_lookalike_is_not_given_builtin_timedelta_seeds():
    source = "def f(delta: project.types.timedelta):\n    if delta.seconds < 60:\n        return True\n"
    fn = D.ast.parse(source).body[0]
    calls = differential._seed_calls(
        [("delta", "project.types.timedelta", None, False)], ["kw"], [], 32,
        cond_seeds=differential._condition_tuple_seeds(fn, None),
    )
    assert calls == []
    from hypothesis import find, settings, strategies as st

    strategy, why = differential._strategy(st, "project.types.timedelta", None, False, [])
    assert strategy is None and "no derivable strategy" in why
    strategy, why = differential._strategy(st, "datetime.timedelta", None, False, [])
    assert strategy is not None, why
    assert find(strategy, lambda value: value == timedelta.max,
                settings=settings(max_examples=20, database=None)) == timedelta.max


def test_timedelta_attribute_evaluator_does_not_execute_subclass_overrides():
    accessed = []

    class HostileTimedelta(timedelta):
        def __getattribute__(self, name):
            if name == "seconds":
                accessed.append(name)
                raise AssertionError("custom attribute code must not run in the expression evaluator")
            return super().__getattribute__(name)

    condition = D._parse_expr("delta.seconds < 60", None)
    assert D._holds(condition, True, [], {"delta": HostileTimedelta(seconds=1)}, {}) is None
    assert accessed == []


def test_timedelta_cutpoint_projection_inverts_only_known_rebindings():
    source = (
        "def f(value: datetime.timedelta | float):\n"
        "    if isinstance(value, datetime.timedelta):\n"
        "        delta = value\n"
        "    else:\n"
        "        delta = dt.timedelta(seconds=value)\n"
        "    delta = abs(delta)\n"
        "    if 3600 <= delta.seconds < 7200:\n"
        "        return True\n"
        "    return False\n"
    )
    fn = D.ast.parse(source).body[0]
    target = next(n for n in D.ast.walk(fn) if isinstance(n, D.ast.If) and "delta.seconds" in D.ast.unparse(n.test))
    adapters = D._projection_adapters(fn, "delta", target.lineno, "value")
    projected = D._project(timedelta(seconds=3600), "any", [], adapters=adapters)
    values = [value for value, _ in projected]

    assert {"timedelta_alias", "abs", "timedelta_seconds"} <= adapters
    assert timedelta(seconds=3600) in values
    assert -timedelta(seconds=3600) in values
    assert 3600.0 in values and -3600.0 in values
    assert all(type(value) in (timedelta, float) for value in values)

    class TimedeltaSubclass(timedelta):
        pass

    assert D._project(TimedeltaSubclass(seconds=3600), "any", [], adapters=adapters) == []

    candidates, reasons = D._candidates_detailed_inproc(
        [("value", "datetime.timedelta | float")], ["3600 <= delta.seconds < 7200"],
        want="true", max_per_condition=16, fn_ast=fn, target_lineno=target.lineno,
    )
    projected_values = [candidate.params.get("value") for candidate in candidates]
    td_values = [value for value in projected_values if type(value) is timedelta]
    float_values = [value for value in projected_values if type(value) is float]
    assert td_values and float_values, reasons
    assert all(3600 <= abs(value).seconds < 7200 for value in td_values)
    assert all(3600 <= timedelta(seconds=abs(value)).seconds < 7200 for value in float_values)

    isolated, isolated_reasons = D.candidates_detailed(
        [("value", "datetime.timedelta | float")], ["3600 <= delta.seconds < 7200"],
        want="true", max_per_condition=4, fn_ast=fn, target_lineno=target.lineno,
    )
    assert isolated, isolated_reasons
    isolated_values = [differential._materialise_desc(candidate.params["value"]) for candidate in isolated]
    assert any(type(value) is timedelta for value in isolated_values)
    assert any(type(value) is float for value in isolated_values)

    unsupported = D.ast.parse(
        "def g(value):\n    delta = custom.convert(value)\n    if delta.seconds == 3600:\n        return True\n"
    ).body[0]
    unsupported_target = next(n for n in D.ast.walk(unsupported) if isinstance(n, D.ast.If))
    unsupported_adapters = D._projection_adapters(unsupported, "delta", unsupported_target.lineno, "value")
    assert unsupported_adapters == set()
    assert D._project(timedelta(seconds=3600), "any", [], adapters=unsupported_adapters) == []

    augmented = D.ast.parse(
        "def h(value):\n    delta = value\n    delta += offset\n    if delta.seconds == 3600:\n        return True\n"
    ).body[0]
    augmented_target = next(n for n in D.ast.walk(augmented) if isinstance(n, D.ast.If))
    augmented_adapters = D._projection_adapters(augmented, "delta", augmented_target.lineno, "value")
    assert augmented_adapters == set()


def test_expected_expr_accepts_bounded_nested_tuple_values_with_exact_types():
    value = [("a", "b"), ("A", "B")]
    ok, restored = inert_from_repr(repr(value))
    assert ok and type(restored[0]) is tuple
    assert value_matches(value, restored)
    assert not value_matches(value, [["a", "b"], ["A", "B"]])


def test_solver_models_keep_the_sequence_bound_not_the_seed_bound():
    """8fd1d4fa regression (mixed-residual): solver models restored from a symbolic sequence were filtered with the
    2-element SEED bound, so `len(xs) > 2` on list[int] lost its only model. Solver models are bounded by K_MAX; the
    default (seed) bound and element-type checks stay strict."""
    shape = ("list", ("int",))
    assert D._matches_shape([0, 0, 0], shape, max_list_len=D.K_MAX)
    assert not D._matches_shape([0] * (D.K_MAX + 1), shape, max_list_len=D.K_MAX)
    assert not D._matches_shape([0, "x", 0], shape, max_list_len=D.K_MAX)
    assert not D._matches_shape([[0, 0, 0]], ("list", shape), max_list_len=D._MAX_SHAPE_LIST_LEN)
    assert not D._matches_shape([0, 0, 0], shape)  # default stays the seed bound
    cands, reasons = D.candidates_detailed([("xs", "list[int]")], ["len(xs) > 2"], want="true", timeout_ms=200,
                                           max_per_condition=4)
    assert cands, reasons
    assert all(type(c.params["xs"]) is list and 2 < len(c.params["xs"]) <= D.K_MAX
               and all(type(v) is int for v in c.params["xs"]) for c in cands)


def test_receiver_field_candidates_survive_the_shape_aware_json_form():
    """8fd1d4fa regression (driver_self_field): a receiver field read in the condition ("self.mode") is generated as an
    env key that is not a declared parameter; the shape-aware _json_form indexed params[k] and the driver sandbox
    crashed (KeyError), so the method's receiver-gated branch was never driven (UNVERIFIED instead of REFUTED)."""
    cands, reasons = D.candidates_detailed([("x", "int")], ["self.mode == 7 and x == 2"], want="true",
                                           timeout_ms=200, max_per_condition=4)
    assert cands, reasons
    assert any(c.params.get("x") == 2 and c.params.get("self.mode") == 7 for c in cands), [c.params for c in cands]
