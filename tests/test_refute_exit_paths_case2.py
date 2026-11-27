"""P0b2 (case): the REFUTED exit paths that tests/test_refute_self_reproduction_case3.py does not exercise: replay that
raises / times out / contradicts the recording, fresh values that differ from the recorded ones, size-truncated witness, driver wall-cap partial
witness, spent replay budget, and the per-class replay cache that omits inputs.

Receipt (scratch/witness-gate.json), one per run that reaches a refutation exit:
  schema        "hlith.refute-gate/1"
  status        "reproduced" | "unstable" | "not-reproduced" | "unstable-unchecked"   (extends the existing values by "not-reproduced")
  exit_path     "differential-call" | "declared-delta" | "repository-test" | "budget-partial"
  tier_a        true iff status == "reproduced"
  why           non-empty whenever status != "reproduced"
  driver_replay "ran" | "cached" | "skipped-budget" | "error" | "none"    (what the in-driver process-dependence replay did for THIS witness)
Invariant (design policy (e), 2026-11-25): verdict REFUTED  <=>  status in {"reproduced", "unstable-unchecked"}; "unstable-unchecked" only for a
COMPLETE witness whose replay is structurally impossible. An INCOMPLETE witness (size-truncated call record, wall-cap partial witness) is
"not-reproduced" -> UNVERIFIED with "incomplete witness" in the stop reason; its call record is kept at scratch/witness-unconfirmed.json, never
scratch/witness.json. A replay that COULD run and failed or disagreed is "unstable" / "not-reproduced" -> UNVERIFIED."""

import json
import subprocess
import types
from pathlib import Path

import pytest

from hlith import differential, sandbox
from hlith.types import Verdict

BASE = "def f(x: int) -> int:\n    return x + 1\n"
BROKEN = "def f(x: int) -> int:\n    return x + 2\n"
NOT_TIER_A = "not a Tier A witness"
_REAL_RUN = sandbox.run_confined


def _fake_only(monkeypatch, role, fake):
    """The driver and the replay both import sandbox.run_confined late: fake only the named one, the other stays real and confined."""
    def route(argv, profile, **kw):
        hit = ("driver" in argv) if role == "driver" else ("-c" in argv)
        return fake(argv, profile, **kw) if hit else _REAL_RUN(argv, profile, **kw)

    monkeypatch.setattr(sandbox, "run_confined", route)


def _tree(tmp_path, base, post, **over):
    for side, body in (("base", base), ("post", post)):
        (tmp_path / side / "pkg").mkdir(parents=True)
        (tmp_path / side / "pkg" / "__init__.py").write_text("")
        (tmp_path / side / "pkg" / "m.py").write_text(body)
        (tmp_path / side / "test_m.py").write_text("import pkg.m as m\n\n\ndef test_f():\n    assert m.f(1) is not None\n")
    (tmp_path / "prop").mkdir()
    kw = dict(base_root=str(tmp_path / "base"), post_root=str(tmp_path / "post"), module="pkg.m", function="f",
              proposer_paths=[str(tmp_path / "prop")], scratch=str(tmp_path / "scratch"), max_examples=20)
    kw.update(over)
    return kw


def _receipt(tmp_path):
    path = tmp_path / "scratch" / "witness-gate.json"
    assert path.is_file(), "no witness-gate.json receipt for a refutation exit"
    r = json.loads(path.read_text())
    assert r.get("schema") == "hlith.refute-gate/1", r
    assert r.get("status") in {"reproduced", "unstable", "not-reproduced", "unstable-unchecked"}, r
    assert r.get("exit_path") in {"differential-call", "declared-delta", "repository-test", "budget-partial"}, r
    assert r.get("tier_a") is (r["status"] == "reproduced"), r
    assert r["status"] == "reproduced" or r.get("why"), r
    assert r.get("driver_replay") in {"ran", "cached", "skipped-budget", "error", "none"}, r
    return r


# ------------------------------------------------------------------ host gate: the replay runs and does not confirm (RED: REFUTED today)

def _assert_downgraded(tmp_path, ob, status):
    assert ob.verdict is Verdict.UNVERIFIED, (ob.verdict, str(ob.witness)[-600:])
    assert _receipt(tmp_path)["status"] == status


def test_exit_replay_raising_is_unverified(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise RuntimeError("injected replay failure")

    monkeypatch.setattr(differential, "replay_witness", boom)
    _assert_downgraded(tmp_path, differential.run_differential(**_tree(tmp_path, BASE, BROKEN)), "not-reproduced")


def test_exit_replay_timing_out_in_every_run_is_unverified(monkeypatch, tmp_path):
    def slow(argv, profile, **kw):
        raise subprocess.TimeoutExpired(argv, 1)

    _fake_only(monkeypatch, "replay", slow)
    _assert_downgraded(tmp_path, differential.run_differential(**_tree(tmp_path, BASE, BROKEN)), "not-reproduced")


def test_exit_replay_seeing_no_divergence_is_unverified(monkeypatch, tmp_path):
    def same(argv, profile, **kw):
        return types.SimpleNamespace(stdout=json.dumps({"k": "ret", "r": "2"}) + "\n", stderr="", returncode=0)

    _fake_only(monkeypatch, "replay", same)
    _assert_downgraded(tmp_path, differential.run_differential(**_tree(tmp_path, BASE, BROKEN)), "not-reproduced")


@pytest.mark.parametrize("pre,post", [("5", "6"), ("1", "6"), ("5", "2")])
def test_exit_stable_fresh_values_differing_from_the_recording_are_not_a_reproduction(monkeypatch, tmp_path, pre, post):
    """Each side repeats itself, but not with the recorded value: per-side repeatability is not agreement with the recorded divergence."""
    def fake(argv, profile, **kw):
        fake.n += 1
        return types.SimpleNamespace(stdout=json.dumps({"k": "ret", "r": pre if fake.n % 2 else post}) + "\n", stderr="", returncode=0)

    fake.n = 0
    monkeypatch.setattr(sandbox, "run_confined", fake)
    (tmp_path / "b").mkdir()
    (tmp_path / "p").mkdir()
    witness = {"module": "pkg.m", "qualname": "f", "args": [1], "kwargs": {}, "env": {}, "pre": {"k": "ret", "r": "1"}, "post": {"k": "ret", "r": "2"}}
    out = differential.replay_witness(witness, str(tmp_path / "b"), str(tmp_path / "p"))
    assert out["reproduced"] is False and out.get("why_not_reproduced"), out


# ------------------------------------------------------------------ structurally unreplayable exits: stay REFUTED, labelled, tier_a false

def test_exit_truncated_witness_is_labelled_and_not_tier_a(monkeypatch, tmp_path):
    monkeypatch.setattr(differential, "_WITNESS_CAP", 16)  # host-side cap only: every call record is "oversized"
    ob = differential.run_differential(**_tree(tmp_path, BASE, BROKEN))
    assert ob.verdict is Verdict.UNVERIFIED and "incomplete witness" in (ob.stop_reason or ""), (ob.verdict, ob.stop_reason, ob.witness)
    assert not (tmp_path / "scratch" / "witness.json").exists(), "an incomplete witness must not be handed on as a witness"
    kept = json.loads((tmp_path / "scratch" / "witness-unconfirmed.json").read_text())
    assert kept["truncated"] is True and kept["sha256"] and kept["size"] > 16 and "args" not in kept, kept
    r = _receipt(tmp_path)
    assert r["status"] == "not-reproduced" and "truncat" in r["why"], r


def _capped_driver(partial):
    def fake(argv, profile, **kw):
        scr = Path(kw["cwd"])
        if partial is not None:
            (scr / "partial-witness.json").write_text(json.dumps({"witness": partial, "record": {}}))
        (scr / "phases.json").write_text(json.dumps({"current": "hypothesis-generation-phase-x",
                                                     "done": {f"finished-phase-number-{i}": 1.0 for i in range(6)}}))
        raise subprocess.TimeoutExpired(argv, 1)

    return fake


@pytest.mark.parametrize("length", [80, 1700, 5000])
def test_exit_budget_partial_keeps_its_not_tier_a_label_and_writes_a_receipt(monkeypatch, tmp_path, length):
    _fake_only(monkeypatch, "driver", _capped_driver("w" * length))
    ob = differential.run_differential(**_tree(tmp_path, BASE, BROKEN))
    assert ob.verdict is Verdict.UNVERIFIED and "incomplete witness" in (ob.stop_reason or ""), (ob.verdict, ob.stop_reason)
    r = _receipt(tmp_path)
    assert r["status"] == "not-reproduced" and r["exit_path"] == "budget-partial", r


def test_exit_driver_cap_without_a_partial_witness_stays_unverified(monkeypatch, tmp_path):
    _fake_only(monkeypatch, "driver", _capped_driver(None))
    ob = differential.run_differential(**_tree(tmp_path, BASE, BROKEN))
    assert ob.verdict is Verdict.UNVERIFIED and "exceeded" in ob.stop_reason, (ob.verdict, ob.stop_reason)
    assert not (tmp_path / "scratch" / "witness-gate.json").exists()


# ------------------------------------------------------------------ driver replay budget and the class-level replay cache

def test_exit_spent_replay_budget_is_recorded_and_the_host_gate_still_decides(tmp_path):
    ob = differential.run_differential(**_tree(tmp_path, BASE, BROKEN, replay_budget=0.0))
    assert ob.verdict is Verdict.REFUTED, (ob.verdict, ob.stop_reason)
    r = _receipt(tmp_path)
    assert r["status"] == "reproduced" and r["driver_replay"] == "skipped-budget", r


# same divergence class (module, name, ret/ret): one input differs only by PROCESS (the pid), one deterministically
_PER_PROCESS = ("import os\n\n\ndef f(x: int) -> int:\n    if x == %(noisy)d:\n        return os.getpid() + 10\n"
                "    if x == %(real)d:\n        return x + 1\n    return x\n")
_PLAIN_OS = "import os\n\n\ndef f(x: int) -> int:\n    return x\n"


@pytest.mark.parametrize("noisy,real", [(7, 1000003), (1000003, 7)])
def test_exit_cached_class_verdict_never_hides_a_deterministic_divergence_on_another_input(tmp_path, noisy, real):
    ob = differential.run_differential(**_tree(tmp_path, _PLAIN_OS,
                                                _PER_PROCESS % {"noisy": noisy, "real": real}, max_examples=40))
    assert ob.verdict is Verdict.REFUTED and f"x={real}" in ob.witness, (ob.verdict, str(ob.witness)[:500], ob.stop_reason)


# ------------------------------------------------------------------ control: an oracle where pre == post must survive the downgrade rule

def test_control_declared_delta_refutation_stays_refuted_and_reproduced(tmp_path):
    delta = {"id": "clamp", "symbol": "pkg.m.f", "kind": "behavior", "claim": "clamp negatives", "input_domain": "", "pre": "", "post": "",
             "predicate": {"type": "typed", "param": "x", "class": "int_neg"}, "expected": {"kind": "returns", "value_repr": "0"}}
    same = "def f(x: int) -> int:\n    return x\n"
    ob = differential.run_differential(**_tree(tmp_path, same, same + "\n# intended change not made\n", deltas=[delta]))
    assert ob.verdict is Verdict.REFUTED and "declared delta" in ob.witness, (ob.verdict, ob.witness, ob.stop_reason)
    r = _receipt(tmp_path)
    assert r["exit_path"] == "declared-delta" and r["status"] == "reproduced", r


def test_control_a_process_dependent_difference_alone_is_unverified(tmp_path):
    only = _PLAIN_OS.replace("    return x\n", "    if x == 7:\n        return os.getpid() + 10\n    return x\n")
    ob = differential.run_differential(**_tree(tmp_path, _PLAIN_OS, only, max_examples=40))
    assert ob.verdict is Verdict.UNVERIFIED and "two fresh processes" in ob.stop_reason, (ob.verdict, ob.stop_reason)
