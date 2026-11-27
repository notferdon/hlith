# SPDX-License-Identifier: Apache-2.0
"""G2 journal, rollback, SIGKILL interruption, and hostile-metadata probes through LocalGateService (case)."""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import signal
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith.contract.errors import EXIT_BOUNDARY, EXIT_LANDED
from hlith.contract.feedback import FeedbackInput
from hlith.contract.identities import new_run_id
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, Verdict
from hlith.effect.api import EffectService
from hlith.gate.api import LocalGateService
from hlith.gate.git_write import head_commit
from hlith.hostio.git_read import HardenedGitRead
from hlith.hostio.integrity import HostIntegrityError, capture_target_identity
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState
from hlith.hostio.verification import LocalVerificationService
from hlith.obligation.api import ObligationEngine


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _head(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD").decode("ascii").strip()


def _head_tree(repo: Path) -> str:
    return _git(repo, "rev-parse", "HEAD^{tree}").decode("ascii").strip()


def _tree_files(repo: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(repo.rglob("*")):
        if ".git" in p.parts or p.is_dir():
            continue
        out[p.relative_to(repo).as_posix()] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def _held_core(**_kw):
    prov = CheckProvenance("checker", "a" * 64, True, False, "b" * 64, 0)
    ev = BoundedEvidence(executions=1, explored="domain", unexplored="open scope")
    obs = tuple(
        Obligation(f"{kind}:pkg.m.f", "pkg.m.f", "preserves", Verdict.HELD, evidence=ev, provenance=prov, account_bound=True)
        for kind in ("signature_binding", "differential")
    )
    return SimpleNamespace(obligations=obs, evidence=())


def _setup_case(tmp_path: Path, monkeypatch):
    state_dir = tmp_path / "state"
    monkeypatch.setenv("HLITH_STATE_DIR", str(state_dir))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Hlith G2")
    _git(repo, "config", "user.email", "g2@example.invalid")
    (repo / "pkg").mkdir()
    (repo / "pkg" / "m.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")

    (repo / "pkg" / "m.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
    patch = _git(repo, "diff", "--binary")
    _git(repo, "checkout", "-q", "--", "pkg/m.py")

    host = LocalHostState(state_dir)
    git_read = HardenedGitRead()
    snaps = LocalSnapshotService(git_read, root=tmp_path / "snaps", cleanup_on_exit=False)
    verifier = LocalVerificationService(host)
    gate = LocalGateService(host, git_read=git_read, snapshot_service=snaps)
    base = snaps.seal_base(repo)
    post = snaps.reconstruct_post(base, patch)
    account = EffectService().build_account(new_run_id(), base, post, patch)
    engine = ObligationEngine(verifier)
    engine._derive = SimpleNamespace(core=_held_core)
    ident = capture_target_identity(repo)
    ve = engine.verify(account, FeedbackInput(), base, post, ident)
    return SimpleNamespace(
        repo=repo,
        state_dir=state_dir,
        patch=patch,
        host=host,
        snaps=snaps,
        verifier=verifier,
        ident=ident,
        gate=gate,
        ve=ve,
        base=base,
        post=post,
    )


def _run_sigkill_land(
    tmp_path: Path,
    repo: Path,
    state_dir: Path,
    patch: bytes,
    ve,
    ident,
    kill_stage: str,
    *,
    leave_index_lock: bool = False,
) -> int:
    """Spawn a real child process running LocalGateService.land and SIGKILL it at kill_stage."""
    src_root = str(Path(__file__).resolve().parents[1] / "src")
    ve_pkl = tmp_path / f"ve-{kill_stage}-{int(leave_index_lock)}.pkl"
    ve_pkl.write_bytes(pickle.dumps((ve, ident)))
    child_code = f"""
import os, pickle, signal
from pathlib import Path
from hlith.gate import api as gate_api
from hlith.gate.api import LocalGateService
from hlith.hostio.git_read import HardenedGitRead
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState
from hlith.hostio.verification import LocalVerificationService

repo = Path({str(repo)!r})
state_dir = Path({str(state_dir)!r})
patch = {patch!r}
ve, ident = pickle.loads(Path({str(ve_pkl)!r}).read_bytes())
host = LocalHostState(state_dir)
git_read = HardenedGitRead()
snaps = LocalSnapshotService(git_read)
verifier = LocalVerificationService(host)
gate = LocalGateService(host, git_read=git_read, snapshot_service=snaps)

stage = {kill_stage!r}
if stage == "before_apply":
    def hook_apply(target, p, expected_tree):
        os.kill(os.getpid(), signal.SIGKILL)
    gate_api.apply_index_and_verify_tree = hook_apply
elif stage == "between_apply_and_commit":
    def hook_commit(target, tree_oid, base_head, msg):
        if {leave_index_lock!r}:
            (target / ".git" / "index.lock").write_bytes(b"")
        os.kill(os.getpid(), signal.SIGKILL)
    gate_api.commit_tree_cas = hook_commit
elif stage == "after_commit_before_clear":
    def hook_clear(j_path, n_path):
        os.kill(os.getpid(), signal.SIGKILL)
    gate_api.clear_journal = hook_clear

gate.land(repo, patch, ve, verifier, ident)
"""
    env = {**os.environ, "HLITH_STATE_DIR": str(state_dir), "PYTHONPATH": src_root}
    cp = subprocess.run([sys.executable, "-c", child_code], env=env, capture_output=True, text=True, timeout=60)
    assert cp.returncode == -signal.SIGKILL, (cp.returncode, cp.stderr, cp.stdout)
    return cp.returncode


def _journal_paths(repo: Path, host: LocalHostState) -> tuple[Path, Path]:
    ident = host.stable_repo_identity(repo)
    j_dir = host.namespace(ident, "journal")
    git_dir = str((repo / ".git").resolve())
    tkey = hashlib.sha256(git_dir.encode("utf-8")).hexdigest()[:24]
    return j_dir / f"landing-{tkey}.json", j_dir / f"landing-{tkey}.nonce"


# ---------------------------------------------------------------------------
# 1. SIGKILL between journal write and git apply -> blocks second land -> recovers cleanly -> later land works
# ---------------------------------------------------------------------------

def test_g2_sigkill_between_journal_write_and_apply_blocks_and_recovers(tmp_path: Path, monkeypatch):
    ctx = _setup_case(tmp_path, monkeypatch)
    base_head = _head(ctx.repo)
    base_tree = _head_tree(ctx.repo)
    before_files = _tree_files(ctx.repo)
    try:
        rc = _run_sigkill_land(tmp_path, ctx.repo, ctx.state_dir, ctx.patch, ctx.ve, ctx.ident, "before_apply")
        assert rc == -signal.SIGKILL
        assert _head(ctx.repo) == base_head
        assert _head_tree(ctx.repo) == base_tree
        assert _tree_files(ctx.repo) == before_files

        # Stale unrecovered journal blocks a fresh landing before recovery
        blocked = ctx.gate.land(ctx.repo, ctx.patch, ctx.ve, ctx.verifier, ctx.ident)
        assert blocked.exit_status == EXIT_BOUNDARY
        assert "unrecovered-journal-exists" in blocked.blocking
        assert _head(ctx.repo) == base_head
        assert _head_tree(ctx.repo) == base_tree

        assert ctx.gate.recover(ctx.repo) == f"recovered:{base_head[:12]}"
        assert _head(ctx.repo) == base_head
        assert _head_tree(ctx.repo) == base_tree
        assert _tree_files(ctx.repo) == before_files
        assert _git(ctx.repo, "status", "--porcelain") == b""
        assert ctx.gate.recover(ctx.repo) == "clean"

        landed = ctx.gate.land(ctx.repo, ctx.patch, ctx.ve, ctx.verifier, ctx.ident)
        assert landed.exit_status == EXIT_LANDED
        assert _head_tree(ctx.repo) == str(ctx.post.tree_oid)
    finally:
        ctx.snaps.close()


# ---------------------------------------------------------------------------
# 2. SIGKILL between git apply and commit (incl. stale index.lock) -> rolls back cleanly -> later land works
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("leave_lock", [False, True])
def test_g2_sigkill_between_apply_and_commit_rolls_back_and_recovers(tmp_path: Path, monkeypatch, leave_lock: bool):
    ctx = _setup_case(tmp_path, monkeypatch)
    base_head = _head(ctx.repo)
    base_tree = _head_tree(ctx.repo)
    before_files = _tree_files(ctx.repo)
    try:
        rc = _run_sigkill_land(tmp_path, ctx.repo, ctx.state_dir, ctx.patch, ctx.ve, ctx.ident, "between_apply_and_commit", leave_index_lock=leave_lock)
        assert rc == -signal.SIGKILL
        assert _head(ctx.repo) == base_head
        assert _tree_files(ctx.repo) != before_files  # post-image applied to worktree

        assert ctx.gate.recover(ctx.repo) == f"recovered:{base_head[:12]}"
        assert not (ctx.repo / ".git" / "index.lock").exists()
        assert _head(ctx.repo) == base_head
        assert _head_tree(ctx.repo) == base_tree
        assert _tree_files(ctx.repo) == before_files
        assert _git(ctx.repo, "status", "--porcelain") == b""
        assert ctx.gate.recover(ctx.repo) == "clean"

        landed = ctx.gate.land(ctx.repo, ctx.patch, ctx.ve, ctx.verifier, ctx.ident)
        assert landed.exit_status == EXIT_LANDED
        assert _head_tree(ctx.repo) == str(ctx.post.tree_oid)
    finally:
        ctx.snaps.close()


# ---------------------------------------------------------------------------
# 3. SIGKILL after commit before clear_journal -> completes recovery and stays idempotent
# ---------------------------------------------------------------------------

def test_g2_sigkill_after_commit_before_clear_completes_and_is_idempotent(tmp_path: Path, monkeypatch):
    ctx = _setup_case(tmp_path, monkeypatch)
    try:
        rc = _run_sigkill_land(tmp_path, ctx.repo, ctx.state_dir, ctx.patch, ctx.ve, ctx.ident, "after_commit_before_clear")
        assert rc == -signal.SIGKILL
        landed_head = _head(ctx.repo)
        assert _head_tree(ctx.repo) == str(ctx.post.tree_oid)

        assert ctx.gate.recover(ctx.repo) == "completed"
        assert _head(ctx.repo) == landed_head
        assert _head_tree(ctx.repo) == str(ctx.post.tree_oid)
        assert ctx.gate.recover(ctx.repo) == "clean"

        retry = ctx.gate.land(ctx.repo, ctx.patch, ctx.ve, ctx.verifier, ctx.ident)
        assert retry.exit_status == EXIT_LANDED
        assert retry.landed_commit == landed_head
    finally:
        ctx.snaps.close()


# ---------------------------------------------------------------------------
# 4. Stale / live index.lock & moved untrusted HEAD refusal controls
# ---------------------------------------------------------------------------

def test_g2_nonempty_index_lock_and_untrusted_moved_head_refuse_safely(tmp_path: Path, monkeypatch):
    ctx = _setup_case(tmp_path, monkeypatch)
    base_head = _head(ctx.repo)
    base_tree = _head_tree(ctx.repo)
    try:
        rc = _run_sigkill_land(tmp_path, ctx.repo, ctx.state_dir, ctx.patch, ctx.ve, ctx.ident, "between_apply_and_commit")
        assert rc == -signal.SIGKILL

        # Non-empty index.lock must NOT be deleted by recovery
        lock = ctx.repo / ".git" / "index.lock"
        lock.write_bytes(b"live-git-lock")
        with pytest.raises(HostIntegrityError, match="index.lock"):
            ctx.gate.recover(ctx.repo)
        assert lock.read_bytes() == b"live-git-lock"
        lock.unlink()

        # Simulate an unrelated commit moving HEAD while journal was pending
        (ctx.repo / "other.txt").write_text("unrelated\n", encoding="utf-8")
        _git(ctx.repo, "add", "other.txt")
        _git(ctx.repo, "commit", "-q", "-m", "other")
        moved_head = _head(ctx.repo)
        moved_tree = _head_tree(ctx.repo)
        assert moved_head != base_head
        assert ctx.gate.recover(ctx.repo) == "untrusted"
        assert _head(ctx.repo) == moved_head
        assert _head_tree(ctx.repo) == moved_tree
    finally:
        ctx.snaps.close()


# ---------------------------------------------------------------------------
# 5. Hostile metadata tampering probes on journal, nonce, config, and worktree
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tamper", ["bad_mac", "bad_nonce", "world_readable_nonce", "symlink_journal", "hostile_config", "unrecognized_worktree"])
def test_g2_hostile_journal_and_metadata_tampering_refuse_without_target_mutation(tmp_path: Path, monkeypatch, tamper: str):
    ctx = _setup_case(tmp_path, monkeypatch)
    base_head = _head(ctx.repo)
    base_tree = _head_tree(ctx.repo)
    before_files = _tree_files(ctx.repo)
    try:
        rc = _run_sigkill_land(tmp_path, ctx.repo, ctx.state_dir, ctx.patch, ctx.ve, ctx.ident, "before_apply")
        assert rc == -signal.SIGKILL
        j_path, n_path = _journal_paths(ctx.repo, ctx.host)
        assert j_path.is_file() and n_path.is_file()

        if tamper == "bad_mac":
            rec = json.loads(j_path.read_text(encoding="utf-8"))
            rec["mac"] = "0" * 64
            j_path.write_text(json.dumps(rec), encoding="utf-8")
        elif tamper == "bad_nonce":
            n_path.write_text("0" * 32, encoding="utf-8")
        elif tamper == "world_readable_nonce":
            os.chmod(n_path, 0o644)
        elif tamper == "symlink_journal":
            secret = tmp_path / "outside.json"
            secret.write_text(j_path.read_text(encoding="utf-8"), encoding="utf-8")
            j_path.unlink()
            os.symlink(secret, j_path)
        elif tamper == "hostile_config":
            marker = tmp_path / "g2.pwned"
            _git(ctx.repo, "config", "core.fsmonitor", f"touch {marker}")
        elif tamper == "unrecognized_worktree":
            (ctx.repo / "pkg" / "m.py").write_text("def f(x):\n    return 'USER_EDIT'\n", encoding="utf-8")

        with pytest.raises(HostIntegrityError):
            ctx.gate.recover(ctx.repo)

        assert _head(ctx.repo) == base_head
        assert _head_tree(ctx.repo) == base_tree
        if tamper == "unrecognized_worktree":
            assert (ctx.repo / "pkg" / "m.py").read_text(encoding="utf-8") == "def f(x):\n    return 'USER_EDIT'\n"
        else:
            assert _tree_files(ctx.repo) == before_files
        assert not (tmp_path / "g2.pwned").exists()
    finally:
        ctx.snaps.close()
