"""review C10: a bool-ANNOTATED parameter is not a closed {True, False} domain.

Python does not enforce the annotation and bool is an int subtype: f(3, 2) is a legal call for `b: bool`. The differential drew only booleans for such a
parameter, so a change that differs ONLY for int arguments of it (base `n + b`, post `(n + b) - b + int(b == True)`: f(3, 2) is 5 vs 3, f(3, -1) is 2 vs 3) was
invisible to it, while the certificate (also a closed Bool domain) proved it. WIDENING ONLY: plain ints are also drawn, and the widening is stated in the evidence.
"""

from pathlib import Path

from hlith import differential
from hlith.types import Verdict

BASE = "def f(n: int, b: bool):\n    return n + b\n"
C10_POST = "def f(n: int, b: bool):\n    return (n + b) - b + int(b == True)\n"


def _run(tmp_path: Path, post_src: str):
    base, post, prop = tmp_path / "base", tmp_path / "post", tmp_path / "prop"
    for d, src in ((base, BASE), (post, post_src)):
        d.mkdir()
        (d / "m.py").write_text(src)
    prop.mkdir()
    (prop / "x").write_text("x")
    return differential.run_differential(
        base_root=str(base), post_root=str(post), import_root="", module="m", function="f", proposer_paths=[str(prop)],
        scratch=str(tmp_path / "scratch"), extra_sys_path=[], max_examples=200, max_seeds=300, adequacy_gate=True,
        require_impacted_slice=False)


def test_a_change_visible_only_for_int_arguments_of_a_bool_parameter_is_refuted(tmp_path):
    ob = _run(tmp_path, C10_POST)
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.witness, ob.stop_reason)
    assert ob.witness and "b=" in ob.witness, ob.witness  # the witness shows the int argument for b


def test_the_identical_post_is_not_refuted_and_the_widening_is_stated(tmp_path):
    ob = _run(tmp_path, BASE)
    assert ob.verdict is not Verdict.REFUTED, (ob.verdict, ob.witness, ob.stop_reason)
    explored = (ob.evidence.explored if ob.evidence else "") or ""
    assert "bool-annotated parameter(s) ['b'] also draw plain ints" in explored, explored[:500]
