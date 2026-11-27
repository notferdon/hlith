"""case (review): the P2(a) caller-test fallback in differential.py is forced for real.

Fixture: `Pump.push` needs `self.gate` (a threading.Lock). The repository test sets it by ASSIGNMENT after construction, so the
synthetic domain is hollow (every draw raises) AND the entry-seeds phase cannot seed the receiver ('not shippable ... set or
changed after construction'): the only way to observe the target is the fallback that records its REAL calls inside the
repository test on both trees. This pins: the agreement note (evidence only, never HELD), the paired-divergence witness
(REFUTED), and the test-side exclusion note (a patch that edits the test's input is not read as the target's change)."""
import re

from hlith import differential
from hlith.types import Verdict

CORE = ("import threading\n\n\nclass Pump:\n    def __init__(self):\n        self.gate = None\n        self.width = 0\n"
        "        self.total = 0\n\n    def push(self, n):\n        with self.gate:\n            self.total += %s\n"
        "        return self.total\n")
TEST = ("import threading\nimport pkg.m as core\n\n\ndef test_push():\n    p = core.Pump()\n    p.gate = threading.Lock()\n"
        "    p.width = %d\n    assert p.push(2) is not None\n")
NODES = [{"node_id": "test_m.py::test_push", "reaches": ["test_m.test_push", "pkg.m.Pump.push"]}]
BASE = "n * self.width"


def _run(tmp_path, post_expr, tb=3, tp=3):
    for side, e, t in (("base", BASE, tb), ("post", post_expr, tp)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(CORE % e)
        (tmp_path / side / "test_m.py").write_text(TEST % t)
    (tmp_path / "prop").mkdir()
    ob = differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="Pump.push",
        proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_seeds=300, max_examples=20,
        impacted_test_nodes=NODES, adequacy_gate=True)
    ev = getattr(ob, "evidence", None)
    text = f"{ob.witness} {ob.stop_reason} {getattr(ev, 'explored', '')} {getattr(ev, 'unexplored', '')}"
    return ob, text


def test_fallback_is_reached_and_agreement_is_evidence_only(tmp_path):
    ob, text = _run(tmp_path, "(n * self.width + 0)")
    assert ob.verdict is Verdict.UNVERIFIED, (ob.verdict, text[:400])
    assert re.search(r"caller-test observation \(P2a\): the target executed 1 / 1 times.*1 stable paired calls agree "
                     r"\(evidence only, never HELD\)", text), text[:600]
    assert "not shippable" in text  # the entry-seeds phase could not seed this receiver: the fallback was the only observer


def test_fallback_paired_divergence_refutes_with_replayable_witness(tmp_path):
    ob, text = _run(tmp_path, "(n * self.width if n != 2 else 0)")
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, text[:400])
    assert "observed through repository test test_m.py::test_push" in str(ob.witness)
    assert "[replay: rerun that test on both trees]" in str(ob.witness)
    assert "return 6" in str(ob.witness) and "return 0" in str(ob.witness)


def test_fallback_excludes_a_changed_test_side_and_never_refutes_on_it(tmp_path):
    # the patch edits the test's own input (width 3 -> 4) AND the target diverges exactly on the test's call: the node is not
    # paired, the exclusion is named, and nothing is claimed from the edited test
    ob, text = _run(tmp_path, "(n * self.width if n != 2 else 0)", 3, 4)
    assert ob.verdict is not Verdict.REFUTED, (ob.verdict, str(ob.witness)[:300])
    assert "1 test node(s) not paired: their test side changed between base and post" in text, text[:600]
    assert "0 stable paired calls agree" in text
