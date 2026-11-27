# SPDX-License-Identifier: Apache-2.0
"""case (review attack-o3: Y2 stub artifact, M1 unrealistic input). Predeclared before the first run.

Witness SELECTION, never the verdict: the verdict is already decided by the first confirmed divergence. What is shown to the
operator must be the real divergence where one exists, not an artifact of the checker's synthetic stand-ins.
  * a divergence whose input is a stub / duck / synthetic stand-in scores worse than one on realistic values;
  * a stand-in on which a side merely FAILED (AttributeError / TypeError / NameError: it lacks what the code reads) is an
    ARTIFACT and scores worst;
  * a None argument scores slightly worse than a realistic value;
  * when the first confirmed divergence is poor, the run keeps looking (bounded) and shows the best one it finds;
  * when every candidate is a stub artifact the witness SAYS so (it shows that the two versions treat such objects
    differently, not what a real object does).
The verdict (REFUTED) is identical with and without selection."""
import json

from hlith import differential
from hlith.types import Verdict


def _ret(r):
    return {"k": "ret", "r": r}


def _exc(t):
    return {"k": "exc", "t": t, "m": ""}


def test_score_orders_artifact_stub_none_clean():
    s = differential._witness_score
    stub = [{"$obj": {"methods": {}, "attrs": {}}}]
    clean = s(_ret("1"), _ret("2"), ["abc"], {})
    none_ = s(_ret("1"), _ret("2"), [None], {})
    stubby = s(_ret("1"), _ret("2"), stub, {})
    artifact = s(_exc("builtins.AttributeError"), _ret("0"), stub, {})
    assert clean < none_ < stubby < artifact, (clean, none_, stubby, artifact)
    duck = [{"__hlith_obj__": "duck", "fields": {"v": 1}}]
    assert s(_ret("1"), _ret("2"), duck, {}) == stubby
    # an AttributeError on a REAL value is behaviour, not an artifact
    assert s(_exc("builtins.AttributeError"), _ret("0"), ["abc"], {}) == clean


def test_artifact_note_is_added_only_for_artifacts():
    assert "stub artifact" in differential._witness_note(differential._witness_score(
        _exc("builtins.AttributeError"), _ret("0"), [{"$obj": {}}], {}))
    assert differential._witness_note(0) == "" and differential._witness_note(13) == ""


_REACH = "import pkg.m as m\n\n\ndef test_reach():\n    m.f\n"
_BASE = 'def f(x, mode="r"):\n    if mode == "w":\n        return x.upper()\n    return x\n'
_POST = 'def f(x, mode="r"):\n    if mode == "w":\n        return x\n    return x\n'


def _run(tmp_path, seeds):
    for side, body in (("base", _BASE), ("post", _POST)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_reach.py").write_text(_REACH)
    (tmp_path / "proposer").mkdir()
    return differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=300, max_examples=30,
        seeds=seeds)


def test_a_stub_artifact_seed_does_not_become_the_witness(tmp_path):
    """The FIRST confirmed divergence is a stand-in (base raises AttributeError: no .upper); a real string diverges too
    (base 'AB', post 'ab'). The witness shown is the real one; the verdict is REFUTED either way."""
    stub_first = ([{"$obj": {"methods": {}, "attrs": {}}}, "w"], {}, "stub-seed")
    ob = _run(tmp_path, [stub_first])
    assert ob.verdict is Verdict.REFUTED, ob
    assert "$obj" not in ob.witness and "Stub(" not in ob.witness and "duck(" not in ob.witness, ob.witness
    assert "stub artifact" not in ob.witness, ob.witness


def test_verdict_does_not_depend_on_selection(tmp_path):
    ob = _run(tmp_path, [])
    assert ob.verdict is Verdict.REFUTED, ob


# ---- review SEL findings (predeclared before the fix) ------------------------------------------------------------------------
# (1) Y2: a stand-in's fake fd 7 is not open, so the base side raises OSError EBADF through an OS call. ANY exception raised
#     on a synthetic stand-in is suspect (the stand-in may lack OR FAKE what the code reads), not only the three attribute
#     errors; it is scored as an artifact and the witness says so.
# (2) S2: an equivalent refactor whose output depends on os.getpid() % 2 is 'confirmed' because the confirmation re-runs in the
#     SAME evaluator process. Behaviour that differs between two FRESH processes of the SAME tree is not a regression and not
#     an equivalence: the verdict is a named UNVERIFIED (never REFUTED on it, never HELD).
def test_any_exception_on_a_stand_in_is_an_artifact():
    s = differential._witness_score
    stub = [{"$obj": {"methods": {}, "attrs": {}}}]
    for t in ("builtins.OSError", "builtins.ValueError", "builtins.KeyError", "builtins.IndexError", "builtins.RuntimeError"):
        assert s(_exc(t), _ret("0"), stub, {}) >= 100, t
    assert s(_exc("builtins.OSError"), _ret("0"), ["abc"], {}) == s(_ret("1"), _ret("2"), ["abc"], {})  # real value: behaviour
    assert "stub artifact" in differential._witness_note(105)


_PID_BASE = "import os\n\n\ndef f(n: int) -> int:\n    return n + os.getpid() % 2\n"
_PID_POST = "import os\n\n\ndef f(n: int) -> int:\n    return os.getpid() % 2 + n\n"


def test_cross_process_nondeterminism_is_named_not_refuted_or_held(tmp_path):
    for side, body in (("base", _PID_BASE), ("post", _PID_POST)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_reach.py").write_text(_REACH)
    (tmp_path / "proposer").mkdir()
    ob = differential.run_differential(
        base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
        proposer_paths=[str(tmp_path / "proposer")], scratch=str(tmp_path / "scratch"), max_seeds=60, max_examples=10,
        adequacy_gate=True)
    assert ob.verdict is Verdict.UNVERIFIED, (ob.verdict, ob.witness)
    txt = (ob.stop_reason or "") + (ob.evidence.unexplored if ob.evidence else "")
    assert "two fresh processes" in txt, txt[-500:]



def test_one_bit_random_is_not_refuted_by_chance(tmp_path):
    """review P4: n + os.urandom(1)[0] % 2 vs the same value reordered. One replay per group let a 1-bit value agree by chance
    (REFUTED in 3 of 4 runs): every group is replayed in several FRESH processes and all outcomes must be identical."""
    base = "import os\n\n\ndef f(n: int) -> int:\n    return n + os.urandom(1)[0] % 2\n"
    post = "import os\n\n\ndef f(n: int) -> int:\n    return os.urandom(1)[0] % 2 + n\n"
    for _ in range(3):
        d = tmp_path / f"r{_}"
        for side, body in (("base", base), ("post", post)):
            (d / side / "pkg").mkdir(parents=True)
            (d / side / "pkg" / "__init__.py").write_text("")
            (d / side / "pkg" / "m.py").write_text(body)
            (d / side / "test_reach.py").write_text(_REACH)
        (d / "proposer").mkdir()
        ob = differential.run_differential(
            base_root=str(d / "base"), post_root=str(d / "post"), module="pkg.m", function="f",
            proposer_paths=[str(d / "proposer")], scratch=str(d / "scratch"), max_seeds=60, max_examples=10, adequacy_gate=True)
        assert ob.verdict is not Verdict.REFUTED, (_, ob.verdict, ob.witness)
