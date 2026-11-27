# SPDX-License-Identifier: Apache-2.0
"""review design plan (G2 landing race), red-first on 5a5bb3f1.

The landing lock was a flock in the HOST-STATE namespace only, and the gate committed whatever the index held (`git commit`). A second
hlith process with ANOTHER state root (TUI default + CLI with HLITH_STATE_DIR) can act on the same target between the gate's
`write-tree == record.post_tree_oid` check and its commit. Fault injection: right after the real apply-and-verify returns True,
another writer either (a) stages an unverified change into the index or (b) lands its own commit (HEAD moves).

Required: the landed commit's tree is exactly the verified post tree, its parent is the record's base, and a commit made by someone
else is never overwritten or reverted (the CAS refuses instead)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith.contract.feedback import FeedbackInput
from hlith.contract.identities import new_run_id
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, Verdict
from hlith.effect.api import EffectService
from hlith.gate import api as gate_api
from hlith.gate.api import LocalGateService
from hlith.hostio.git_read import HardenedGitRead
from hlith.hostio.integrity import capture_target_identity
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState
from hlith.hostio.verification import LocalVerificationService
from hlith.obligation.api import ObligationEngine


def _git(repo: Path, *a: str, env: dict | None = None) -> str:
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True,
                          env={**os.environ, **(env or {})}).stdout.strip()


def _held_core(**kw):
    prov = CheckProvenance("checker", "a" * 64, True, False, "b" * 64, 0)
    ev = BoundedEvidence(executions=1, explored="domain", unexplored="open scope")
    obs = tuple(Obligation(f"{kind}:m.f", "m.f", "preserves", Verdict.HELD, evidence=ev, provenance=prov, account_bound=True)
                for kind in ("signature_binding", "differential"))
    return SimpleNamespace(obligations=obs, evidence=())


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "m.py").write_text("def f(x):\n    return x\n")
    (repo / "other.py").write_text("O = 1\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n")
    patch = subprocess.run(["git", "-C", str(repo), "diff", "--no-color"], capture_output=True, check=True).stdout
    _git(repo, "checkout", "-q", "--", "m.py")
    host = LocalHostState(tmp_path / "state")
    git_read = HardenedGitRead()
    snaps = LocalSnapshotService(git_read)
    verifier = LocalVerificationService(host)
    gate = LocalGateService(host, git_read=git_read, snapshot_service=snaps)
    base = snaps.seal_base(repo)
    post = snaps.reconstruct_post(base, patch)
    account = EffectService().build_account(new_run_id(), base, post, patch)
    engine = ObligationEngine(verifier)
    engine._derive = SimpleNamespace(core=_held_core)
    ident = capture_target_identity(repo)
    ve = engine.verify(account, FeedbackInput(), base, post, ident)
    return SimpleNamespace(repo=repo, patch=patch, ve=ve, verifier=verifier, gate=gate, ident=ident, tmp=tmp_path)


def _other_writer_lands(repo: Path, tmp: Path, rel: str = "other.py", body: bytes = b"O = 2\n") -> str:
    """Another landing (its own verified tree: base + one file change) committed through plumbing, as a concurrent gate would."""
    idx = str(tmp / "other.index")
    e = {"GIT_INDEX_FILE": idx}
    _git(repo, "read-tree", "HEAD", env=e)
    blob = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=body, capture_output=True,
                          check=True).stdout.decode().strip()
    _git(repo, "update-index", "--cacheinfo", f"100644,{blob},{rel}", env=e)
    tree = _git(repo, "write-tree", env=e)
    new = _git(repo, "commit-tree", tree, "-p", "HEAD", "-m", "other landing")
    _git(repo, "update-ref", "HEAD", new)
    return new


@pytest.mark.parametrize("interleave", ["stage-unverified-change", "other-landing-moves-head", "other-landing-same-path"])
def test_a_concurrent_writer_between_verify_and_commit_never_yields_an_unverified_or_clobbering_commit(env, monkeypatch, interleave):
    base_head = _git(env.repo, "rev-parse", "HEAD")
    real_apply = gate_api.apply_index_and_verify_tree
    other: dict = {}

    def apply_then_interleave(target, patch, expected):
        ok = real_apply(target, patch, expected)
        if interleave == "stage-unverified-change":
            (env.repo / "other.py").write_text("O = 666  # never verified\n")
            _git(env.repo, "add", "other.py")
        elif interleave == "other-landing-moves-head":
            other["commit"] = _other_writer_lands(env.repo, env.tmp)
        else:  # OCR lead on 8bc33d42 (api.py:262-265): the other writer committed the SAME content to the touched path
            other["commit"] = _other_writer_lands(env.repo, env.tmp, "m.py", b"def f(x):\n    return x + 1\n")
        return ok

    monkeypatch.setattr(gate_api, "apply_index_and_verify_tree", apply_then_interleave)
    r = env.gate.land(env.repo, env.patch, env.ve, env.verifier, env.ident)
    head = _git(env.repo, "rev-parse", "HEAD")
    if interleave == "stage-unverified-change":
        assert r.outcome == "landed", r
        assert _git(env.repo, "rev-parse", "HEAD^{tree}") == str(env.ve.record.post_tree_oid), "landed tree is not the verified tree"
        assert _git(env.repo, "rev-parse", "HEAD~1") == base_head
        assert r.landed_commit == head
        assert _git(env.repo, "show", "HEAD:other.py") == "O = 1", "an unverified staged change rode the landing commit"
    elif interleave == "other-landing-same-path":
        assert head == other["commit"] and r.outcome == "refused" and "head-moved" in " ".join(r.blocking), r
        assert _git(env.repo, "status", "--porcelain") == "", "rollback restored the stale base over the other writer's commit"
        assert (env.repo / "m.py").read_text() == "def f(x):\n    return x + 1\n"
    else:
        assert head == other["commit"], "the other writer's landed commit was overwritten"
        assert _git(env.repo, "show", "HEAD:other.py") == "O = 2", "the other writer's change was reverted"
        assert r.outcome == "refused" and r.landed_commit is None, r
        assert "head-moved" in " ".join(r.blocking), r.blocking


def test_an_update_ref_failure_with_head_unchanged_is_not_reported_as_a_head_move(env, monkeypatch):
    """OCR lead on eb96f219 (git_write.py:211-213): a held ref lock makes update-ref fail while HEAD did NOT move. The landing is still
    refused and rolled back to the base, but under its own name, never "head-moved-during-landing"."""
    base_head = _git(env.repo, "rev-parse", "HEAD")
    branch = _git(env.repo, "symbolic-ref", "HEAD")
    lock = env.repo / ".git" / (branch + ".lock")
    real_apply = gate_api.apply_index_and_verify_tree

    def apply_then_lock(target, patch, expected):
        ok = real_apply(target, patch, expected)
        lock.write_text("")  # another git process holds the branch ref lock
        return ok

    monkeypatch.setattr(gate_api, "apply_index_and_verify_tree", apply_then_lock)
    r = env.gate.land(env.repo, env.patch, env.ve, env.verifier, env.ident)
    lock.unlink()
    assert r.outcome == "refused" and "head-moved" not in " ".join(r.blocking), r.blocking
    assert _git(env.repo, "rev-parse", "HEAD") == base_head and _git(env.repo, "status", "--porcelain") == ""


def test_recovery_calls_a_landing_completed_only_if_head_carries_exactly_the_verified_tree(env, monkeypatch):
    """D1 writer half (case): recovery must bind the VERIFIED post tree, not only per-path blobs. Images
    record blob ids, not modes: a commit on the base with the post blobs but a flipped exec bit passed the old per-path check and was
    reported "completed". Fault injection: the landing dies at its commit (journal left), then such a commit becomes HEAD."""
    base_head = _git(env.repo, "rev-parse", "HEAD")

    def die(*a, **k):
        raise KeyboardInterrupt("killed at commit")

    monkeypatch.setattr(gate_api, "commit_tree_cas", die)
    with pytest.raises(KeyboardInterrupt):
        env.gate.land(env.repo, env.patch, env.ve, env.verifier, env.ident)
    (env.repo / "m.py").chmod(0o755)  # worktree already holds the post blob (apply --index); only the mode differs
    _git(env.repo, "add", "m.py")
    _git(env.repo, "commit", "-qm", "same blobs, different mode")
    assert _git(env.repo, "rev-parse", "HEAD~1") == base_head and _git(env.repo, "status", "--porcelain") == ""
    assert _git(env.repo, "rev-parse", "HEAD^{tree}") != str(env.ve.record.post_tree_oid)
    assert env.gate.recover(env.repo) == "untrusted"
