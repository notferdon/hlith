"""R1/E2 in miniature: a changed statement that writes `self.<field>[key] = ...` where the constructor default of <field> is None.

requests PreparedRequest.prepare_content_length writes `self.headers["Content-Length"] = builtin_str(length)`; PreparedRequest.__init__
sets `self.headers = None`. The differential varies a receiver FIELD like a parameter (`self.headers`: no annotation, default None).
For such a parameter the generic domain holds ONE fixed dict ({"a": 1}), so a draw where the field is a mapping AND the body is sized
is rare; the pipeline run on the real case reported "changed statement never completed on any explored input (it raised on every
entry)" and refused UNVERIFIED instead of showing the Content-Length 3 -> 4 witness.

This test is the same shape with no repository around it. Before the field-mapping widening it must be UNVERIFIED (named gap, never
HELD); after it, the change of the written value is REFUTED with a witness. The completion rule is untouched: a statement that never
completes is still never HELD.
"""

from pathlib import Path

from hlith import differential
from hlith.types import Verdict

BASE = '''
def super_len(o):
    total_length = None
    if hasattr(o, "__len__"):
        total_length = len(o)
    elif hasattr(o, "len"):
        total_length = o.len
    if total_length is None:
        total_length = 0
    return max(0, total_length)


class Prep:
    def __init__(self):
        self.headers = None
        self.method = None

    def set_len(self, body):
        if body is not None:
            length = super_len(body)
            if length:
                # to Transfer-Encoding: chunked.
                self.headers["Content-Length"] = str(length)
'''
POST = BASE.replace('self.headers["Content-Length"] = str(length)', 'self.headers["Content-Length"] = str(length + 1)')


def _run(tmp_path: Path, post_src: str):
    base, post, prop = tmp_path / "base", tmp_path / "post", tmp_path / "prop"
    for d, src in ((base, BASE), (post, post_src)):
        d.mkdir()
        (d / "m.py").write_text(src)
    prop.mkdir()
    (prop / "x").write_text("x")
    return differential.run_differential(
        base_root=str(base), post_root=str(post), import_root="", module="m", function="Prep.set_len",
        proposer_paths=[str(prop)], scratch=str(tmp_path / "scratch"), extra_sys_path=[], max_examples=200, max_seeds=300,
        adequacy_gate=True, require_impacted_slice=False)


def test_a_changed_write_into_a_default_none_field_is_refuted_not_left_unverified(tmp_path):
    ob = _run(tmp_path, POST)
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.witness, ob.stop_reason)
    assert ob.witness, "a REFUTED verdict must carry the witness (the exact call and the two outcomes)"


def test_an_unchanged_write_is_still_not_refuted(tmp_path):
    """The widening must not invent divergences: the identical post is never REFUTED."""
    ob = _run(tmp_path, BASE)
    assert ob.verdict is not Verdict.REFUTED, (ob.verdict, ob.witness, ob.stop_reason)


def test_the_widening_is_stated_in_the_evidence_never_silent(tmp_path):
    """The widened receiver-state pool is named in the explored text (which fields, which domain), only when it applied."""
    ob = _run(tmp_path, POST)
    explored = (ob.evidence.explored if ob.evidence else "") or ""
    assert "receiver-state pool widened" in explored and "self.headers" in explored and "mappings" in explored, explored[:600]

