# SPDX-License-Identifier: Apache-2.0
"""G1 (CONTRACT: all-and-only NONEMPTY every-obligation HELD permits landing): a derivation that yields a genuinely EMPTY
obligation set must refuse and leave the target unchanged. A comment-only patch is NOT such a case (it derives obligations
that hold); this drives the real ObligationEngine -> real signed record -> real gate with the derivation core returning
no obligation at all, and a control where the same stack lands one held, account-bound obligation."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith.contract.errors import EXIT_LANDED
from hlith.contract.feedback import FeedbackInput
from hlith.contract.identities import new_run_id
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, ObligationSet, Verdict
from hlith.effect.api import EffectService
from hlith.gate.api import LocalGateService
from hlith.hostio.git_read import HardenedGitRead
from hlith.hostio.integrity import capture_target_identity
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState
from hlith.hostio.verification import LocalVerificationService
from hlith.obligation.api import ObligationEngine
from hlith.types import EXIT_NOT_DERIVED


def _git(repo: Path, *a: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True).stdout.strip()


def _env(tmp_path: Path, monkeypatch, core):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "m.py").write_text("def f(x):\n    return x\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "init")
    (repo / "m.py").write_text("def f(x):\n    return x  # note\n")
    patch = subprocess.run(["git", "-C", str(repo), "diff"], capture_output=True, check=True).stdout
    _git(repo, "checkout", "--", "m.py")

    host = LocalHostState(tmp_path / "state")
    git_read = HardenedGitRead()
    snaps = LocalSnapshotService(git_read)
    verifier = LocalVerificationService(host)
    gate = LocalGateService(host, git_read=git_read, snapshot_service=snaps)
    base = snaps.seal_base(repo)
    post = snaps.reconstruct_post(base, patch)
    account = EffectService().build_account(new_run_id(), base, post, patch)
    engine = ObligationEngine(verifier)
    engine._derive = SimpleNamespace(core=core)  # the ONLY stand-in: what the derivation returned
    return repo, patch, gate, verifier, engine, account, base, post, capture_target_identity(repo)


def _empty_core(**kw):
    return SimpleNamespace(obligations=(), evidence=())


def _held_core(**kw):
    prov = CheckProvenance("checker", "a" * 64, True, False, "b" * 64, 0)
    ev = BoundedEvidence(executions=1, explored="domain", unexplored="open scope")
    obs = tuple(Obligation(f"{kind}:m.f", "m.f", "preserves", Verdict.HELD, evidence=ev, provenance=prov, account_bound=True)
                for kind in ("signature_binding", "differential"))
    return SimpleNamespace(obligations=obs, evidence=())


def _verify_and_land(env):
    repo, patch, gate, verifier, engine, account, base, post, ident = env
    ve = engine.verify(account, FeedbackInput(), base, post, ident)
    return ve, gate.land(repo, patch, ve, verifier, ident)


def test_empty_derived_set_is_refused_not_derived_and_target_unchanged(tmp_path, monkeypatch):
    env = _env(tmp_path, monkeypatch, _empty_core)
    repo = env[0]
    head = _git(repo, "rev-parse", "HEAD")
    ve, receipt = _verify_and_land(env)
    got = [(o.obligation_id, o.verdict) for o in ve.obligations.obligations]
    assert got == [("no-obligation", Verdict.NOT_DERIVED)], got
    assert receipt.outcome == "refused" and receipt.exit_status == EXIT_NOT_DERIVED == 11, receipt
    assert tuple(receipt.blocking) == ("no-obligation",) and receipt.landed_commit is None, receipt
    assert _git(repo, "rev-parse", "HEAD") == head and _git(repo, "status", "--porcelain") == ""
    assert (repo / "m.py").read_text() == "def f(x):\n    return x\n"


def test_control_same_stack_with_one_held_account_bound_obligation_lands(tmp_path, monkeypatch):
    env = _env(tmp_path, monkeypatch, _held_core)
    ve, receipt = _verify_and_land(env)
    assert [o.verdict for o in ve.obligations.obligations] == [Verdict.HELD, Verdict.HELD]
    assert receipt.outcome == "landed" and receipt.exit_status == EXIT_LANDED, receipt


def test_an_empty_obligation_set_cannot_be_constructed():
    with pytest.raises(ValueError):
        ObligationSet(())
