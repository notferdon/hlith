"""An incomplete witness never supports REFUTED; a complete witness that cannot be replayed stays REFUTED and says so; collect mode is gated too."""

import json
import subprocess
import types
from pathlib import Path

import pytest

from hlith import differential, sandbox
from hlith.types import Verdict

BASE = "def f(x: int) -> int:\n    return x + 1\n"
BROKEN = "def f(x: int) -> int:\n    return x + 2\n"
_REAL_RUN = sandbox.run_confined


def run(tmp_path, base, post, **over):
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_m.py").write_text("import pkg.m as m\n\n\ndef test_f():\n    assert m.f(1) is not None\n")
    (tmp_path / "prop").mkdir()
    kw = dict(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
              proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_examples=20)
    kw.update(over)
    return differential.run_differential(**kw)


def receipt(tmp_path):
    return json.loads((tmp_path / "scratch" / "witness-gate.json").read_text())


def withheld(tmp_path, ob):
    assert ob.verdict is Verdict.UNVERIFIED and "incomplete witness" in ob.stop_reason, (ob.verdict, ob.witness, ob.stop_reason)
    assert receipt(tmp_path)["status"] == "not-reproduced" and receipt(tmp_path)["tier_a"] is False


def test_a_size_truncated_witness_is_unverified_and_not_left_as_the_refuting_call(monkeypatch, tmp_path):
    monkeypatch.setattr(differential, "_WITNESS_CAP", 16)
    withheld(tmp_path, run(tmp_path, BASE, BROKEN))
    assert differential.read_witness(str(tmp_path / "scratch")) is None
    assert (tmp_path / "scratch" / "witness-unconfirmed.json").is_file()


def test_a_wall_cap_partial_witness_is_unverified(monkeypatch, tmp_path):
    def capped(argv, profile, **kw):
        if "driver" not in argv:
            return _REAL_RUN(argv, profile, **kw)
        (Path(kw["cwd"]) / "partial-witness.json").write_text(json.dumps({"witness": "w" * 5000, "record": {}}))
        raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(sandbox, "run_confined", capped)
    withheld(tmp_path, run(tmp_path, BASE, BROKEN))


def test_a_collect_mode_witness_passes_the_same_gate_and_its_records_are_no_verdict_evidence(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise RuntimeError("injected replay failure")

    monkeypatch.setattr(differential, "replay_witness", boom)
    ob = run(tmp_path, BASE, BROKEN, collect_divergences=5)
    assert ob.verdict is Verdict.UNVERIFIED, (ob.verdict, ob.witness)
    records = differential.read_divergences(str(tmp_path / "scratch"))
    assert records["divergences"] and records["verdict_evidence"] is False
    assert not (tmp_path / "scratch" / "witness.json").exists(), "an unconfirmed call must not be handed on as the refuting call"


def test_control_a_complete_witness_without_a_call_stays_refuted_and_unchecked(tmp_path):
    ob = run(tmp_path, BASE, "def g(x: int) -> int:\n    return x + 1\n")
    assert ob.verdict is Verdict.REFUTED and "not a Tier A witness" in ob.witness, (ob.verdict, ob.witness, ob.stop_reason)
    assert receipt(tmp_path)["status"] == "unstable-unchecked"
    assert "pkg.m.f no longer defined in post tree" in ob.witness, ob.witness  # this case, not any other witness without a call


@pytest.mark.parametrize("where", ["args", "kwargs", "ctor"])
def test_a_recorded_stub_is_unreplayable_from_the_record_alone_and_nothing_runs(monkeypatch, tmp_path, where):
    ran = []
    monkeypatch.setattr(sandbox, "run_confined", lambda *a, **k: ran.append(1))
    stub = {"$obj": {"methods": {"lines": {"return": [1]}}}}
    witness = {"module": "pkg.m", "qualname": "f", "args": [stub] if where == "args" else [1], "kwargs": {"o": stub} if where == "kwargs" else {},
               "env": {}, "pre": {"k": "ret", "r": "1"}, "post": {"k": "ret", "r": "2"}}
    if where == "ctor":
        witness.update(qualname="K.f", receiver={"cls": "K", "kind": "instance", "ctor": [[stub], {}]})
    out = differential.replay_witness(witness, str(tmp_path), str(tmp_path))
    assert out["replayable"] is False and "behavioural stub" in out["why"] and not ran, out


@pytest.mark.parametrize("where", ["args", "ctor"])
def test_control_the_same_kind_without_a_stub_is_replayed_and_must_reproduce(monkeypatch, tmp_path, where):
    same = types.SimpleNamespace(stdout=json.dumps({"k": "ret", "r": "1"}) + "\n", stderr="", returncode=0)
    monkeypatch.setattr(sandbox, "run_confined", lambda *a, **k: same)  # both trees answer alike: the recording is not confirmed
    witness = {"module": "pkg.m", "qualname": "f", "args": [{"obj": 1}], "kwargs": {}, "env": {}, "pre": {"k": "ret", "r": "1"},
               "post": {"k": "ret", "r": "2"}}
    if where == "ctor":
        witness.update(qualname="K.f", receiver={"cls": "K", "kind": "instance", "ctor": [[[1, 2]], {}]})
    out = differential.replay_witness(witness, str(tmp_path), str(tmp_path))
    assert out["replayable"] is True and out["reproduced"] is False and out["why_not_reproduced"], out


@pytest.mark.parametrize("post,verdict", [(BASE, Verdict.HELD), (BROKEN, Verdict.REFUTED)], ids=["held", "refuted"])
def test_the_marker_namespace_gap_is_disclosed_without_changing_the_verdict(tmp_path, post, verdict):
    ob = run(tmp_path, BASE, post if post != BASE else BASE + "# same\n")
    assert ob.verdict is verdict, (ob.verdict, ob.stop_reason)
    assert differential._MARKER_INPUT_NOTE in ob.evidence.unexplored and '"$obj"' in ob.evidence.unexplored, ob.evidence.unexplored
