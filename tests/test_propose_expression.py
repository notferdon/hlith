"""propose-deltas can EMIT the broader expression candidate (returns_expr) when the closed-form finder reproduces ALL observed pairs:
never default-included, validated by the real grammar and delta validator, labelled as covering untried inputs, rendered for review."""
import subprocess
import sys

from hlith import expected_expr, propose
from hlith.runtime import validate_deltas

CF = {"attempted": True, "param": "o", "form": "len(o.encode('utf-8'))", "pairs": 6}


def test_expression_delta_is_a_validated_returns_expr_delta_over_a_typed_predicate():
    d = propose.expression_delta("requests.utils.super_len", CF, "abcd1234")
    assert d is not None
    v = validate_deltas([d])[0]  # the real delta validator accepts it
    assert v["expected"] == {"kind": "returns_expr", "expr": "len(o.encode('utf-8'))"}
    assert v["predicate"] == {"type": "typed", "param": "o", "class": "str_nonempty"}
    assert expected_expr.validate_expected_expr(d["expected"]["expr"], ["o"])[0]  # and the closed grammar, with the callable's parameter names
    assert "EXPRESSION CANDIDATE" in d["claim"] and "including untried" in d["claim"] and "unreviewed" in d["claim"]
    assert d["id"].startswith("proposed-abcd1234-expr")


def test_the_candidate_expression_really_evaluates_to_the_observed_pairs():
    d = propose.expression_delta("m.f", CF, "t")
    for text, n in (("é", 2), ("日本", 6), ("😀", 4), ("é", 3)):
        ok, val = expected_expr.evaluate_expected_expr(d["expected"]["expr"], {"o": text})
        assert ok and val == n


def test_no_expression_candidate_without_a_form_that_reproduces_every_pair():
    assert propose.expression_delta("m.f", {"attempted": True, "param": "o", "form": None, "pairs": 5}, "t") is None
    assert propose.expression_delta("m.f", {"attempted": False}, "t") is None
    assert propose.expression_delta("m.f", None, "t") is None
    assert propose.expression_delta("m.f", {"attempted": True, "param": "o; evil()", "form": "len(o)", "pairs": 2}, "t") is None  # parameter must be a plain name


def test_render_labels_the_expression_candidate_and_what_it_covers():
    res = {"callables": [{"symbol": "m.f", "verdict": "refuted", "divergences_seen": 6, "explored": 100, "divergences_listed": 6, "truncated": False,
                          "stopped_reason": "x", "excluded": {}, "mode": "expression", "pattern": None, "outliers": [], "scratch_rows": [],
                          "closed_form": CF, "preview": {"ran": True, "uncovered_count": 0, "uncovered": [], "truncated": False, "explored": 90, "verdict": "held"},
                          "candidate_deltas": ["proposed-t-expr"]}], "listed": []}
    t = propose.render(res)
    assert "EXPRESSION CANDIDATE" in t and "EVERY input where o is a non-empty str" in t and "including untried" in t
    assert "len(o.encode('utf-8'))" in t and "never default-included" in t and "0 outside divergence" in t


def test_the_cli_exposes_the_expression_flag_separately_from_include_all():
    p = subprocess.run([sys.executable, "-m", "hlith.cli", "propose-deltas", "--help"], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and "--expression" in p.stdout and "--include-all" in p.stdout


def test_expression_candidate_only_for_a_single_parameter_callable():
    # f(o, mode='a') observed only as f('é'): a claim over EVERY call would include f('x', mode='b'), never observed
    assert propose.expression_delta("m.f", CF, "t", names=["o", "mode"]) is None
    assert "other parameters unconstrained, never varied" in propose.expression_refusal(["o", "mode"])
    assert propose.expression_delta("m.f", CF, "t", names=["o"]) is not None and propose.expression_refusal(["o"]) is None
    assert propose.expression_delta("m.f", CF, "t", names=["self", "o"]) is not None  # self/cls are not parameters of the claim
    assert propose.expression_delta("m.f", CF, "t", names=["cls", "o"]) is not None
    assert propose.expression_delta("m.f", CF, "t", names=[]) is None  # parameters unknown: refuse rather than assume


def test_render_says_why_the_expression_candidate_was_refused_for_a_two_parameter_callable():
    res = {"callables": [{"symbol": "m.f", "verdict": "refuted", "divergences_seen": 6, "explored": 100, "divergences_listed": 6, "truncated": False,
                          "stopped_reason": "x", "excluded": {}, "mode": "expression-unavailable", "pattern": None, "outliers": [], "scratch_rows": [],
                          "closed_form": CF, "preview": None, "candidate_deltas": [], "expression_refusal": propose.expression_refusal(["o", "mode"])}], "listed": []}
    assert "other parameters unconstrained, never varied" in propose.render(res)


def test_preview_wording_is_a_bounded_exploration_not_a_verification():
    res = {"callables": [{"symbol": "m.f", "verdict": "refuted", "divergences_seen": 6, "explored": 100, "divergences_listed": 6, "truncated": False,
                          "stopped_reason": "x", "excluded": {}, "mode": "expression", "pattern": None, "outliers": [], "scratch_rows": [], "closed_form": CF,
                          "preview": {"ran": True, "uncovered_count": 0, "uncovered": [], "truncated": False, "explored": 90, "verdict": "held"},
                          "candidate_deltas": ["proposed-t-expr"]}], "listed": []}
    t = propose.render(res)
    assert "bounded exploration: 0 outside divergences found in 90 comparisons (preview not truncated); not a proof" in t


def _names(tmp_path, src, qualname):
    f = tmp_path / "m.py"
    f.write_text(src)
    return propose._param_names(tmp_path, "m.py", qualname)


def test_every_parameter_kind_counts_so_only_a_truly_single_parameter_callable_qualifies(tmp_path):
    src = ("def one(o):\n    pass\n"
           "def kw(o, *, mode='a'):\n    pass\n"
           "def var(o, *rest):\n    pass\n"
           "def kws(o, **kw):\n    pass\n"
           "def pos(o, /, p):\n    pass\n"
           "class C:\n    def m(self, o):\n        pass\n    @classmethod\n    def c(cls, o):\n        pass\n")
    assert propose.expression_refusal(_names(tmp_path, src, "one")) is None
    for q in ("kw", "var", "kws", "pos"):
        assert "other parameters unconstrained, never varied" in propose.expression_refusal(_names(tmp_path, src, q)), q
    assert propose.expression_refusal(_names(tmp_path, src, "C.m")) is None  # self is not a parameter of the claim
    assert propose.expression_refusal(_names(tmp_path, src, "C.c")) is None


def test_the_callable_is_resolved_by_its_qualified_name_not_the_first_bare_match(tmp_path):
    src = "def k(o):\n    pass\nclass C:\n    def k(self, a, b):\n        pass\n"
    assert _names(tmp_path, src, "C.k") == ["self", "a", "b"]  # not the module-level k(o)
    assert propose.expression_refusal(_names(tmp_path, src, "C.k")) is not None
    assert _names(tmp_path, src, "k") == ["o"]
    assert _names(tmp_path, src, "Nope.k") == [] and _names(tmp_path, src, "missing") == []  # unknown: no names, so no expression claim
