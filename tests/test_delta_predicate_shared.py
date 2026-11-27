import pytest

from hlith import differential
from hlith.agent import capture


_TOO_MANY_NODES = " or ".join(f"x == {value}" for value in range(12))


def _delta(expr):
    return {
        "id": "shared-expr",
        "symbol": "pkg.mod.f",
        "kind": "behavior",
        "claim": "the declared predicate is supported",
        "input_domain": "",
        "pre": "",
        "post": "",
        "predicate": {"type": "expr", "param": "x", "expr": expr},
        "expected": {"kind": "returns", "value_repr": "None"},
    }


@pytest.mark.parametrize(
    "expr",
    [_TOO_MANY_NODES, "x.count('a') > 0"],
    ids=("51-ast-nodes", "unsupported-count-method"),
)
def test_capture_and_differential_refuse_unsupported_predicates_with_same_reason(expr):
    tree, errors = differential._validate_expr("x", expr)
    assert tree is None
    assert errors
    checkable, differential_errors = differential._validate_deltas([_delta(expr)])
    assert not checkable
    assert differential_errors == [f"delta shared-expr: {'; '.join(errors)}"]

    with pytest.raises(ValueError) as capture_error:
        capture.validate_delta(_delta(expr))

    assert str(capture_error.value) == "; ".join(errors)
