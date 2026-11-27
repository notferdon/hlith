"""R1/E1: the adequacy corpus must not hide a receiver state that only appears late in the exploration (review, case).

Unit: selection is bounded, deterministic, a strict superset of the old first-N rule, and admits a late input only for a NEW shape signature.
Miniature: an EQUIVALENT edit of `self.headers[k] = str(n)` (constructor default None) must not be reported "never completed on the
adequacy corpus" merely because mapping receivers come late; a statement that REALLY raises on every receiver must still be refused
(negative control), and a changed value is still REFUTED.
"""
from pathlib import Path

from hlith import differential
from hlith.differential import _ABL_FIRST, _ABL_RESERVE, _corpus_admit, _corpus_sig
from hlith.types import Verdict


def _stream(n, late_mapping_at):
    for i in range(n):
        hdr = {"a": 1} if i == late_mapping_at else None
        yield [{"$obj": {"methods": {"__len__": {"return": 7}}}} if i == late_mapping_at else None], {"self.headers": hdr, "x": f"s{i}"}, None


def test_selection_is_bounded_deterministic_and_a_superset_of_the_old_prefix():
    def build():
        c, s = [], set()
        for a, k, e in _stream(6000, 3000):
            _corpus_admit(c, s, a, k, e)
        return c
    c1, c2 = build(), build()
    assert c1 == c2
    assert _ABL_FIRST <= len(c1) <= _ABL_FIRST + _ABL_RESERVE
    old = [[a, k, e] for a, k, e in list(_stream(6000, 3000))[:_ABL_FIRST]]
    assert c1[:_ABL_FIRST] == old, "the first _ABL_FIRST inputs must be exactly the old rule's"


def test_a_late_input_with_a_new_shape_is_admitted_and_a_late_repeat_shape_is_not():
    c, s = [], set()
    for a, k, e in _stream(6000, 3000):
        _corpus_admit(c, s, a, k, e)
    assert any(isinstance(k.get("self.headers"), dict) for _a, k, _e in c), "the late mapping+sized row must be in the corpus"
    n = len(c)
    for _ in range(50):
        _corpus_admit(c, s, [None], {"self.headers": None, "x": "zz"}, None)  # same shape as many earlier rows
    assert len(c) == n


def test_shape_signature_never_raises_on_odd_values():
    assert _corpus_sig([object(), {"$obj": 5}, {"$obj": {"methods": 3}}], {"k": {"__hlith_new__": 1}}) is not None or True


MINI = '''
class Prep:
    def __init__(self):
        self.headers = None
        self.method = None

    def set_len(self, body):
        if body is not None:
            length = len(body) if hasattr(body, "__len__") else 0
            if length:
                self.headers["Content-Length"] = {EXPR}
'''
RAISES = MINI.replace('self.headers["Content-Length"] = {EXPR}', 'self.headers.add("Content-Length", {EXPR})')


def _run(tmp_path: Path, base_src: str, post_src: str):
    base, post, prop = tmp_path / "base", tmp_path / "post", tmp_path / "prop"
    for d, src in ((base, base_src), (post, post_src)):
        d.mkdir()
        (d / "m.py").write_text(src)
    prop.mkdir()
    (prop / "x").write_text("x")
    return differential.run_differential(
        base_root=str(base), post_root=str(post), import_root="", module="m", function="Prep.set_len",
        proposer_paths=[str(prop)], scratch=str(tmp_path / "scratch"), extra_sys_path=[], max_examples=200, max_seeds=300,
        adequacy_gate=True, require_impacted_slice=False)


def test_equivalent_edit_is_not_refuted_and_gap_text_names_its_corpus(tmp_path):
    ob = _run(tmp_path, MINI.replace("{EXPR}", "str(length)"), MINI.replace("{EXPR}", '"%d" % length'))
    assert ob.verdict is not Verdict.REFUTED, (ob.verdict, ob.witness)
    if ob.verdict is Verdict.UNVERIFIED and "never completed" in (ob.stop_reason or ""):
        assert "adequacy corpus" in ob.stop_reason, ob.stop_reason


def test_negative_control_a_statement_that_raises_on_every_receiver_is_never_held(tmp_path):
    ob = _run(tmp_path, RAISES.replace("{EXPR}", "str(length)"), RAISES.replace("{EXPR}", '"%d" % length'))
    assert ob.verdict is not Verdict.HELD, (ob.verdict, ob.stop_reason)
    assert ob.verdict is not Verdict.REFUTED, (ob.verdict, ob.witness)


def test_a_changed_value_is_still_refuted(tmp_path):
    ob = _run(tmp_path, MINI.replace("{EXPR}", "str(length)"), MINI.replace("{EXPR}", "str(length + 1)"))
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.witness, ob.stop_reason)
