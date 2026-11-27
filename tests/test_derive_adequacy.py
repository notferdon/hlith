# SPDX-License-Identifier: Apache-2.0
"""Gate 1: derive turns review's white-box adequacy gate ON by default (measurement-only switch to turn it off)."""
import subprocess

import pytest

from hlith import derive as dv
from hlith.derive import make_derive
from hlith.types import ProposedEffect, Verdict

NUM_OLD = "def f(x: int) -> int:\n    return x + 1\n"
NUM_NEW = "def f(x: int) -> int:\n    return 1 + x\n"
# an edit confined to a branch ordinary inputs never enter (design review's class): with the gate OFF this can land
GUARD_OLD = "def f(n: int) -> int:\n    if n.bit_length() > 64 and n % 7 == 6:\n        return 1\n    return 0\n"
GUARD_NEW = "def f(n: int) -> int:\n    if n.bit_length() > 64 and n % 7 == 6:\n        return 2\n    return 0\n"


def _run(tmp_path, old, new, **kw):
    repo = tmp_path / "r"
    repo.mkdir(parents=True)
    for a in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"]):
        subprocess.run(["git", "-C", str(repo), *a], check=True)
    (repo / "m.py").write_text(old)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "b"], check=True)
    (repo / "m.py").write_text(new)
    diff = subprocess.run(["git", "-C", str(repo), "diff"], check=True, capture_output=True, text=True).stdout
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", "m.py"], check=True)
    prop = tmp_path / "p"
    prop.mkdir(parents=True)
    (prop / "x").write_text("x")
    return make_derive(proposer_paths=[str(prop)], **kw)(repo, ProposedEffect(unified_diff=diff, proposer_id="t", touched_files=("m.py",)))


def _capture(monkeypatch, tmp_path, old, new, **kw):
    seen = {}
    real = dv.differential.run_differential

    def stub(*a, **k):
        seen.update(k)
        return real(*a, **k)

    monkeypatch.setattr(dv.differential, "run_differential", stub)
    _run(tmp_path, old, new, **kw)
    return seen


def test_default_is_on_and_reaches_run_differential(monkeypatch, tmp_path):
    assert dv.ADEQUACY_GATE_DEFAULT is True
    monkeypatch.delenv("HLITH_ADEQUACY_GATE", raising=False)
    assert _capture(monkeypatch, tmp_path, GUARD_OLD, GUARD_NEW).get("adequacy_gate") is True


@pytest.mark.parametrize("val", ["0", "off", "false"])
def test_env_switch_turns_it_off_for_measurement(monkeypatch, tmp_path, val):
    monkeypatch.setenv("HLITH_ADEQUACY_GATE", val)
    assert not _capture(monkeypatch, tmp_path, GUARD_OLD, GUARD_NEW).get("adequacy_gate")


def test_parameter_overrides_env(monkeypatch, tmp_path):
    monkeypatch.setenv("HLITH_ADEQUACY_GATE", "0")
    assert _capture(monkeypatch, tmp_path / "on", GUARD_OLD, GUARD_NEW, adequacy_gate=True).get("adequacy_gate") is True
    monkeypatch.delenv("HLITH_ADEQUACY_GATE")
    assert not _capture(monkeypatch, tmp_path / "off", GUARD_OLD, GUARD_NEW, adequacy_gate=False).get("adequacy_gate")


def test_waiver_survives_the_flip(monkeypatch, tmp_path):
    from hlith import delta_rel
    from hlith import derive as dv

    real = delta_rel.check_callable  # a caller that PROVES the repo class universe clean (derive does not yet)
    monkeypatch.setattr(delta_rel, "check_callable",
                        lambda *a, **k: real(*a, **{"repo_universe": {"subclasses": [], "complete": True}, **k}))
    monkeypatch.setattr(dv, "ADEQUACY_PROVED_WAIVER", True)  # the waiver is OFF by default (review D07-D09); mechanism test only
    seen = _capture(monkeypatch, tmp_path, NUM_OLD, NUM_NEW)
    assert seen.get("adequacy_gate") is True and seen.get("adequacy_proved") == "delta_rel:m.f"


def test_unexercised_branch_edit_is_not_held_with_the_gate_on(tmp_path):
    s = _run(tmp_path, GUARD_OLD, GUARD_NEW)
    diff_obs = [o for o in s.obligations if o.obligation_id.startswith("differential")]
    assert diff_obs and all(o.verdict is not Verdict.HELD for o in diff_obs), [(o.verdict, o.witness, o.stop_reason) for o in diff_obs]


def test_off_is_recorded_as_not_enforced(tmp_path):
    s = _run(tmp_path, NUM_OLD, "def f(x: int) -> int:\n    return x + 1  # same\n", adequacy_gate=False)
    held = [o for o in s.obligations if o.obligation_id.startswith("differential") and o.verdict is Verdict.HELD]
    for o in held:
        assert "adequacy: not enforced" in o.evidence.explored


def test_proved_waiver_is_off_by_default(monkeypatch, tmp_path):
    from hlith import derive as dv

    assert dv.ADEQUACY_PROVED_WAIVER is False
    assert not _capture(monkeypatch, tmp_path, NUM_OLD, NUM_NEW).get("adequacy_proved")
