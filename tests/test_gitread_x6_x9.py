# SPDX-License-Identifier: Apache-2.0
"""Exit tests X6, X7, X8/X8c, and X9 (incl. F2 and F3) for the structural Git-read choke point.

Self-contained red-first suite written against public/stable seams on bfaeb00c:
- X6: fail-closed on spawn OSError, timeout, non-zero exit (incl. real cyclic [include]),
  config parse failure / valueless keys, and F3 silent-empty ([color] diff=always,
  extensions.objectformat).
- X7: LocalSnapshotService.seal_base refuses hostile targets via `git config --file` only
  (no -C/--git-dir/--work-tree on the target) and exports the exact HEAD tree on clean targets.
- X8/X8c: config mutation between vet and command (known-exec key -> no marker + raise/discard;
  any config change -> raise/discard); mid-run same-tree HEAD move refused by LocalGateService.land
  when expected_head is supplied (feature-checked so bfaeb00c goes red for landing on moved HEAD).
- X9: target .git (config, index bytes+mtime, HEAD, refs, packed-refs, objects, no lock/cache
  debris) and worktree unchanged after every refusal and clean read (incl. F2 safe_git_read status).
"""

from __future__ import annotations

import hashlib
import inspect
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from hlith.agent import checkpoint as ckpt
from hlith.contract.feedback import FeedbackInput
from hlith.contract.identities import new_run_id
from hlith.contract.legacy import BoundedEvidence, CheckProvenance, Obligation, Verdict
from hlith.effect.api import EffectService
from hlith.gate.api import LocalGateService
from hlith.hostio.git_read import HardenedGitRead, safe_git_read
from hlith.hostio.integrity import HostIntegrityError, capture_target_identity
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState
from hlith.hostio.verification import LocalVerificationService
from hlith.obligation.api import ObligationEngine
from hlith.operator import gitq
from hlith.operator.tui import changes


_CLEAN_GIT_ENV = {
    "PATH": os.environ.get("PATH", os.defpath),
    "LANG": "C",
    "LC_ALL": "C",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_AUTHOR_NAME": "Test",
    "GIT_AUTHOR_EMAIL": "test@example.invalid",
    "GIT_COMMITTER_NAME": "Test",
    "GIT_COMMITTER_EMAIL": "test@example.invalid",
}

_REFUSE_EXCS = (HostIntegrityError, RuntimeError, OSError, subprocess.SubprocessError)


def _git(repo: Path, *args: str) -> str:
    cp = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=_CLEAN_GIT_ENV,
        capture_output=True,
        text=True,
        check=True,
    )
    return cp.stdout.strip()


def _init_repo(tmp_path: Path, name: str = "repo", files: dict[str, str] | None = None) -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], env=_CLEAN_GIT_ENV, check=True)
    payload = files or {
        "m.py": "def f(x: int) -> int:\n    return x + 1\n",
        "sub/helper.txt": "hello\n",
    }
    for rel, body in payload.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    return repo


def _marker(tmp_path: Path, name: str = "hook.sh") -> tuple[Path, Path]:
    marker = tmp_path / f"{name}.fired"
    script = tmp_path / name
    script.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n", encoding="utf-8")
    script.chmod(0o755)
    return marker, script


def _sha_file(path: Path) -> tuple[bytes, int] | None:
    if not path.exists() and not path.is_symlink():
        return None
    st = path.lstat()
    if path.is_symlink():
        return (os.readlink(path).encode("utf-8", "surrogateescape"), st.st_mtime_ns)
    return (path.read_bytes(), st.st_mtime_ns)


def _snapshot_target(repo: Path) -> dict[str, object]:
    git_dir = repo / ".git"
    refs_dir = git_dir / "refs"
    refs_snap: list[tuple[str, bytes | str]] = []
    if refs_dir.exists():
        for p in sorted(refs_dir.rglob("*")):
            rel = p.relative_to(refs_dir).as_posix()
            if p.is_symlink():
                refs_snap.append((rel, f"SYMLINK:{os.readlink(p)}"))
            elif p.is_file():
                refs_snap.append((rel, p.read_bytes()))
            elif p.is_dir():
                refs_snap.append((rel + "/", "DIR"))
    obj_dir = git_dir / "objects"
    objects_list = sorted(
        p.relative_to(obj_dir).as_posix()
        for p in obj_dir.rglob("*")
    ) if obj_dir.exists() else []
    git_entries = sorted(p.name for p in git_dir.iterdir())
    wt_files: list[tuple[str, str]] = []
    for dp, dns, fns in os.walk(repo, followlinks=False):
        dns[:] = sorted(d for d in dns if d != ".git")
        for fn in sorted(fns):
            fp = Path(dp) / fn
            rel = fp.relative_to(repo).as_posix()
            if fp.is_symlink():
                wt_files.append((rel, f"SYMLINK:{os.readlink(fp)}"))
            else:
                wt_files.append((rel, hashlib.sha256(fp.read_bytes()).hexdigest()))
    return {
        "config": _sha_file(git_dir / "config"),
        "index": _sha_file(git_dir / "index"),
        "HEAD": _sha_file(git_dir / "HEAD"),
        "packed_refs": _sha_file(git_dir / "packed-refs"),
        "refs": refs_snap,
        "objects": objects_list,
        "git_entries": git_entries,
        "worktree": wt_files,
    }


def _assert_x9_preserved(repo: Path, before: dict[str, object]) -> None:
    after = _snapshot_target(repo)
    assert after == before, f"target mutated during read/refusal:\nbefore={before!r}\nafter={after!r}"
    git_dir = repo / ".git"
    assert not (git_dir / "index.lock").exists()
    assert not (git_dir / "hlith-cache").exists()


def _assert_all_runners_refuse(repo: Path, tmp_path: Path, head_sha: str, tree_sha: str) -> None:
    reason = HardenedGitRead().repository_hostile_reason(repo)
    assert isinstance(reason, str) and reason, f"HardenedGitRead did not refuse: {reason!r}"

    q_reason = gitq.refusal(repo)
    assert isinstance(q_reason, str) and q_reason, f"gitq.refusal failed open: {q_reason!r}"

    with pytest.raises(_REFUSE_EXCS):
        safe_git_read(repo, "rev-parse", "HEAD")

    with pytest.raises(_REFUSE_EXCS):
        HardenedGitRead().head_tree(repo)

    with pytest.raises(_REFUSE_EXCS):
        HardenedGitRead().export_tree(repo, tree_sha, tmp_path / f"exp_{new_run_id()}")

    assert gitq.git(repo, "rev-parse", "HEAD") == b""
    assert gitq.text(repo, "rev-parse", "HEAD") == ""
    with pytest.raises(RuntimeError):
        gitq.git(repo, "rev-parse", "HEAD", check=True)
    with pytest.raises(RuntimeError):
        gitq.text(repo, "rev-parse", "HEAD", check=True)

    with pytest.raises(OSError):
        proc = gitq.popen(repo, ["status", "--porcelain=v1"])
        try:
            proc.kill()
            proc.wait()
        except Exception:
            pass

    with pytest.raises(_REFUSE_EXCS):
        LocalSnapshotService(root=tmp_path / "snaps").seal_base(repo)

    assert ckpt._target_has_commit(str(repo), head_sha) is False


# ---------------------------------------------------------------------------
# X6: Fail-closed on spawn OSError, timeout, non-zero exit, parse failure, F3
# ---------------------------------------------------------------------------


def test_x6_spawn_oserror_refuses_every_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path)
    head_sha = _git(repo, "rev-parse", "HEAD")
    tree_sha = _git(repo, "rev-parse", "HEAD^{tree}")

    def fail_run(*_a, **_kw):
        raise OSError("simulated spawn failure")

    def fail_popen(*_a, **_kw):
        raise OSError("simulated popen failure")

    monkeypatch.setattr(subprocess, "run", fail_run)
    monkeypatch.setattr(subprocess, "Popen", fail_popen)

    # Note: HardenedGitRead().repository_hostile_reason must return a refusal string (not propagate raw OSError)
    # and gitq.refusal / gitq.git / gitq.text must refuse instead of returning None / b"" / "".
    reason = HardenedGitRead().repository_hostile_reason(repo)
    assert isinstance(reason, str) and reason
    q_reason = gitq.refusal(repo)
    assert isinstance(q_reason, str) and q_reason
    with pytest.raises(_REFUSE_EXCS):
        safe_git_read(repo, "rev-parse", "HEAD")
    with pytest.raises(_REFUSE_EXCS):
        HardenedGitRead().head_tree(repo)
    with pytest.raises(_REFUSE_EXCS):
        HardenedGitRead().export_tree(repo, tree_sha, tmp_path / "exp_oserr")
    assert gitq.git(repo, "rev-parse", "HEAD") == b""
    assert gitq.text(repo, "rev-parse", "HEAD") == ""
    with pytest.raises(RuntimeError):
        gitq.git(repo, "rev-parse", "HEAD", check=True)
    with pytest.raises(RuntimeError):
        gitq.text(repo, "rev-parse", "HEAD", check=True)
    with pytest.raises(OSError):
        gitq.popen(repo, ["status", "--porcelain=v1"])
    assert ckpt._target_has_commit(str(repo), head_sha) is False


def test_x6_spawn_timeout_refuses_every_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path)
    head_sha = _git(repo, "rev-parse", "HEAD")
    tree_sha = _git(repo, "rev-parse", "HEAD^{tree}")

    def timeout_run(cmd, *_a, **_kw):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1)

    class _TimeoutProc:
        pid = 999999

        def __init__(self, cmd, *_a, **_kw):
            self._cmd = cmd
            self.returncode = None
            self.stdout = None
            self.stderr = None

        def communicate(self, input=None, timeout=None):
            raise subprocess.TimeoutExpired(cmd=self._cmd, timeout=timeout or 1)

        def poll(self):
            return 1

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 1

    monkeypatch.setattr(subprocess, "run", timeout_run)
    monkeypatch.setattr(subprocess, "Popen", _TimeoutProc)

    reason = HardenedGitRead().repository_hostile_reason(repo)
    assert isinstance(reason, str) and reason
    q_reason = gitq.refusal(repo)
    assert isinstance(q_reason, str) and q_reason
    with pytest.raises(_REFUSE_EXCS):
        safe_git_read(repo, "rev-parse", "HEAD")
    with pytest.raises(_REFUSE_EXCS):
        HardenedGitRead().head_tree(repo)
    with pytest.raises(_REFUSE_EXCS):
        HardenedGitRead().export_tree(repo, tree_sha, tmp_path / "exp_timeout")
    assert gitq.git(repo, "rev-parse", "HEAD") == b""
    assert gitq.text(repo, "rev-parse", "HEAD") == ""
    with pytest.raises(RuntimeError):
        gitq.git(repo, "rev-parse", "HEAD", check=True)
    with pytest.raises(RuntimeError):
        gitq.text(repo, "rev-parse", "HEAD", check=True)
    with pytest.raises(OSError):
        gitq.popen(repo, ["status", "--porcelain=v1"])
    assert ckpt._target_has_commit(str(repo), head_sha) is False


def test_x6_nonzero_config_exit_simulated_refuses_every_runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path)
    head_sha = _git(repo, "rev-parse", "HEAD")
    tree_sha = _git(repo, "rev-parse", "HEAD^{tree}")

    def nz_run(cmd, *_a, **_kw):
        return subprocess.CompletedProcess(cmd, 128, b"", b"fatal: simulated config failure\n")

    class _NzProc:
        pid = 999999

        def __init__(self, cmd, *_a, **_kw):
            self.args = cmd
            self.returncode = 128
            self.stdout = None
            self.stderr = None

        def communicate(self, input=None, timeout=None):
            return (b"", b"fatal: simulated config failure\n")

        def poll(self):
            return 128

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 128

    monkeypatch.setattr(subprocess, "run", nz_run)
    monkeypatch.setattr(subprocess, "Popen", _NzProc)

    _assert_all_runners_refuse(repo, tmp_path, head_sha, tree_sha)


def test_x6_real_cyclic_include_fixture_refuses_every_runner_and_preserves(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    head_sha = _git(repo, "rev-parse", "HEAD")
    tree_sha = _git(repo, "rev-parse", "HEAD^{tree}")
    marker, script = _marker(tmp_path, "cyc_fsm.sh")
    loop_cfg = repo / ".git" / "loop.cfg"
    loop_cfg.write_text(f"[include]\n\tpath = {loop_cfg}\n", encoding="utf-8")
    with (repo / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write(f"[include]\n\tpath = {loop_cfg}\n[core]\n\tfsmonitor = {script}\n")

    before = _snapshot_target(repo)
    _assert_all_runners_refuse(repo, tmp_path, head_sha, tree_sha)
    assert not marker.exists()
    _assert_x9_preserved(repo, before)


def test_x6_parse_failure_and_valueless_key_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Real valueless config entry ([core]\n\tfsmonitor without '=') emits `core.fsmonitor\0` with no newline.
    repo = _init_repo(tmp_path, "valueless")
    head_sha = _git(repo, "rev-parse", "HEAD")
    tree_sha = _git(repo, "rev-parse", "HEAD^{tree}")
    with (repo / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write("[core]\n\tfsmonitor\n")

    before = _snapshot_target(repo)
    _assert_all_runners_refuse(repo, tmp_path, head_sha, tree_sha)
    _assert_x9_preserved(repo, before)

    # Simulated truncated/malformed NUL output from config --list --null
    repo2 = _init_repo(tmp_path, "malformed")
    head2 = _git(repo2, "rev-parse", "HEAD")
    tree2 = _git(repo2, "rev-parse", "HEAD^{tree}")

    def bad_parse_run(cmd, *_a, **_kw):
        return subprocess.CompletedProcess(cmd, 0, b"local\0core.fsmonitor", b"")

    class _BadParseProc:
        pid = 999999

        def __init__(self, cmd, *_a, **_kw):
            self.args = cmd
            self.returncode = 0
            self.stdout = None
            self.stderr = None

        def communicate(self, input=None, timeout=None):
            return (b"local\0core.fsmonitor", b"")

        def poll(self):
            return 0

        def kill(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(subprocess, "run", bad_parse_run)
    monkeypatch.setattr(subprocess, "Popen", _BadParseProc)
    _assert_all_runners_refuse(repo2, tmp_path, head2, tree2)


def test_x6_f3_silent_empty_color_diff_and_extensions_objectformat(tmp_path: Path) -> None:
    clean = _init_repo(tmp_path, "clean_ctrl")
    (clean / "m.py").write_text("def f(x: int) -> int:\n    return x + 99\n", encoding="utf-8")
    clean_change = changes.uncommitted(clean)
    assert clean_change is not None and clean_change.patch

    # F3a: [color] diff=always must either be refused by vet OR pinned off so uncommitted() returns the real patch.
    repo_col = _init_repo(tmp_path, "color_always")
    with (repo_col / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write("[color]\n\tdiff = always\n")
    (repo_col / "m.py").write_text("def f(x: int) -> int:\n    return x + 99\n", encoding="utf-8")
    if gitq.refusal(repo_col) is None:
        c_col = changes.uncommitted(repo_col)
        assert c_col is not None and c_col.patch == clean_change.patch

    # F3b: [extensions] objectformat=sha1 at format version 0 must be refused everywhere (never silent empty).
    repo_ext = _init_repo(tmp_path, "ext_objfmt")
    with (repo_ext / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write("[extensions]\n\tobjectformat = sha1\n")
    (repo_ext / "m.py").write_text("def f(x: int) -> int:\n    return x + 99\n", encoding="utf-8")
    assert HardenedGitRead().repository_hostile_reason(repo_ext) is not None
    assert gitq.refusal(repo_ext) is not None
    with pytest.raises(_REFUSE_EXCS):
        safe_git_read(repo_ext, "status", "--porcelain=v1")
    assert gitq.git(repo_ext, "status", "--porcelain=v1") == b""
    with pytest.raises(RuntimeError):
        gitq.git(repo_ext, "status", "--porcelain=v1", check=True)


# ---------------------------------------------------------------------------
# X7: Seam B (LocalSnapshotService.seal_base)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["fsmonitor", "unknown_key", "valueless"])
def test_x7_seal_base_hostile_refuses_and_only_spawns_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    repo = _init_repo(tmp_path, f"hostile_{kind}")
    marker, script = _marker(tmp_path, f"x7_{kind}.sh")
    with (repo / ".git" / "config").open("a", encoding="utf-8") as fh:
        if kind == "fsmonitor":
            fh.write(f"[core]\n\tfsmonitor = {script}\n")
        elif kind == "unknown_key":
            fh.write("[core]\n\thlithunknown = 1\n")
        else:
            fh.write("[core]\n\tfsmonitor\n")

    spawns: list[tuple[list[str], str | None]] = []
    real_run = subprocess.run
    real_popen = subprocess.Popen

    def spy_run(cmd, *a, **kw):
        spawns.append(([str(x) for x in cmd], str(kw["cwd"]) if kw.get("cwd") is not None else None))
        return real_run(cmd, *a, **kw)

    def spy_popen(cmd, *a, **kw):
        spawns.append(([str(x) for x in cmd], str(kw["cwd"]) if kw.get("cwd") is not None else None))
        return real_popen(cmd, *a, **kw)

    monkeypatch.setattr(subprocess, "run", spy_run)
    monkeypatch.setattr(subprocess, "Popen", spy_popen)

    before = _snapshot_target(repo)
    with pytest.raises(HostIntegrityError):
        LocalSnapshotService(root=tmp_path / "snaps").seal_base(repo)

    assert not marker.exists()
    _assert_x9_preserved(repo, before)
    assert spawns, "expected vet spawn"
    resolved_repo = str(repo.resolve())
    for cmd, cwd in spawns:
        assert "config" in cmd and any(a == "--file" or a.startswith("--file=") for a in cmd), (
            f"non-config-file git spawn on hostile target: {cmd}"
        )
        assert "-C" not in cmd and "--git-dir" not in cmd and "--work-tree" not in cmd, (
            f"vet started git inside target repo instead of --file: {cmd}"
        )
        assert cwd is None or not Path(cwd).resolve().is_relative_to(resolved_repo), (
            f"vet spawned with cwd inside target repo: {cwd}"
        )


def test_x7_seal_base_clean_target_exports_exact_head_tree(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "clean_seal")
    expected_tree = _git(repo, "rev-parse", "HEAD^{tree}")
    before = _snapshot_target(repo)

    snap = LocalSnapshotService(root=tmp_path / "snaps").seal_base(repo)
    assert str(snap.tree_oid) == expected_tree
    assert (snap.path / "m.py").read_text(encoding="utf-8") == (repo / "m.py").read_text(encoding="utf-8")
    assert (snap.path / "sub" / "helper.txt").read_text(encoding="utf-8") == "hello\n"
    _assert_x9_preserved(repo, before)


# ---------------------------------------------------------------------------
# X8 & X8c: Vet-to-command race & mid-run same-tree HEAD move
# ---------------------------------------------------------------------------


def _install_vet_to_command_race(monkeypatch: pytest.MonkeyPatch, repo: Path, append_cfg: str) -> None:
    real_run = subprocess.run
    real_popen = subprocess.Popen
    injected = {"done": False}

    def maybe_mutate(cmd: list[str]) -> None:
        if injected["done"]:
            return
        if "config" not in cmd and any(op in cmd for op in ("status", "rev-parse")):
            with (repo / ".git" / "config").open("a", encoding="utf-8") as fh:
                fh.write(append_cfg)
            injected["done"] = True

    def hooked_run(cmd, *a, **kw):
        maybe_mutate([str(x) for x in cmd])
        return real_run(cmd, *a, **kw)

    def hooked_popen(cmd, *a, **kw):
        maybe_mutate([str(x) for x in cmd])
        return real_popen(cmd, *a, **kw)

    monkeypatch.setattr(subprocess, "run", hooked_run)
    monkeypatch.setattr(subprocess, "Popen", hooked_popen)


def test_x8_race_known_exec_key_between_vet_and_command(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path, "race_exec")
    marker, script = _marker(tmp_path, "race_fsm.sh")
    _install_vet_to_command_race(monkeypatch, repo, f"\n[core]\n\tfsmonitor = {script}\n")

    with pytest.raises(_REFUSE_EXCS):
        safe_git_read(repo, "status", "--porcelain=v1")
    assert not marker.exists()

    # Reset config to clean for the gitq leg (default check=False discards -> b""; check=True raises RuntimeError)
    _git(repo, "config", "--unset-all", "core.fsmonitor")
    _install_vet_to_command_race(monkeypatch, repo, f"\n[core]\n\tfsmonitor = {script}\n")
    assert gitq.git(repo, "rev-parse", "HEAD") == b""
    assert not marker.exists()

    _git(repo, "config", "--unset-all", "core.fsmonitor")
    _install_vet_to_command_race(monkeypatch, repo, f"\n[core]\n\tfsmonitor = {script}\n")
    with pytest.raises(RuntimeError):
        gitq.git(repo, "rev-parse", "HEAD", check=True)
    assert not marker.exists()


def test_x8_race_any_config_change_between_vet_and_command_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path, "race_benign")
    _install_vet_to_command_race(monkeypatch, repo, "\n[user]\n\tname = raced\n")
    with pytest.raises(_REFUSE_EXCS):
        safe_git_read(repo, "rev-parse", "HEAD")

    _git(repo, "config", "--unset-all", "user.name")
    _install_vet_to_command_race(monkeypatch, repo, "\n[user]\n\tname = raced2\n")
    assert gitq.git(repo, "rev-parse", "HEAD") == b""

    _git(repo, "config", "--unset-all", "user.name")
    _install_vet_to_command_race(monkeypatch, repo, "\n[user]\n\tname = raced3\n")
    with pytest.raises(RuntimeError):
        gitq.git(repo, "rev-parse", "HEAD", check=True)


def _held_core(**_kw):
    prov = CheckProvenance("checker", "a" * 64, True, False, "b" * 64, 0)
    ev = BoundedEvidence(executions=1, explored="domain", unexplored="open scope")
    obs = tuple(
        Obligation(f"{kind}:m.f", "m.f", "preserves", Verdict.HELD, evidence=ev, provenance=prov, account_bound=True)
        for kind in ("signature_binding", "differential")
    )
    return SimpleNamespace(obligations=obs, evidence=())


def test_x8c_mid_run_same_tree_head_move_refused_by_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _init_repo(tmp_path, "gate_x8c", {"m.py": "def f(x):\n    return x\n"})
    (repo / "m.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
    _git(repo, "add", "m.py")
    patch = subprocess.run(
        ["git", "-C", str(repo), "diff", "--cached", "--no-color"],
        env=_CLEAN_GIT_ENV,
        capture_output=True,
        check=True,
    ).stdout
    _git(repo, "reset", "-q", "--hard", "HEAD")

    host = LocalHostState(tmp_path / "state")
    git_read = HardenedGitRead()
    snaps = LocalSnapshotService(git_read, root=tmp_path / "snaps")
    verifier = LocalVerificationService(host)
    gate = LocalGateService(host, git_read=git_read, snapshot_service=snaps)

    reviewed_head = _git(repo, "rev-parse", "HEAD")
    base = snaps.seal_base(repo)
    post = snaps.reconstruct_post(base, patch)
    account = EffectService().build_account(new_run_id(), base, post, patch)
    engine = ObligationEngine(verifier)
    engine._derive = SimpleNamespace(core=_held_core)
    ident = capture_target_identity(repo)
    ve = engine.verify(account, FeedbackInput(), base, post, ident)

    # Concurrent same-tree commit advances main while .git/HEAD ("ref: refs/heads/main") bytes and tree stay identical.
    _git(repo, "commit", "--allow-empty", "-qm", "concurrent-same-tree-move")
    moved_head = _git(repo, "rev-parse", "HEAD")
    assert moved_head != reviewed_head

    if "expected_head" in inspect.signature(gate.land).parameters:
        receipt = gate.land(repo, patch, ve, verifier, ident, expected_head=reviewed_head)
    else:
        receipt = gate.land(repo, patch, ve, verifier, ident)

    assert receipt.outcome == "refused", f"gate landed onto moved HEAD {moved_head}: {receipt}"
    assert receipt.landed_commit is None
    assert _git(repo, "rev-parse", "HEAD") == moved_head


# ---------------------------------------------------------------------------
# X9: Target preservation (bytes + index mtime + refs/objects/worktree) & F2
# ---------------------------------------------------------------------------


def test_x9_f2_safe_git_read_status_preserves_index_bytes_and_mtime(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path, "f2_idx")
    time.sleep(0.02)
    (repo / "m.py").touch()  # racily clean entry: without GIT_OPTIONAL_LOCKS=0, git status rewrites .git/index

    before = _snapshot_target(repo)
    out = safe_git_read(repo, "status", "--porcelain=v1")
    assert out == ""
    _assert_x9_preserved(repo, before)

    assert gitq.git(repo, "status", "--porcelain=v1") == b""
    _assert_x9_preserved(repo, before)

    assert str(HardenedGitRead().head_tree(repo)) == _git(repo, "rev-parse", "HEAD^{tree}")
    _assert_x9_preserved(repo, before)


def test_x9_hostile_refusals_preserve_target_and_leave_no_debris(tmp_path: Path) -> None:
    other = _init_repo(tmp_path, "other")

    cases = []
    # 1. fsmonitor
    r_fsm = _init_repo(tmp_path, "h_fsm")
    h_fsm, t_fsm = _git(r_fsm, "rev-parse", "HEAD"), _git(r_fsm, "rev-parse", "HEAD^{tree}")
    m_fsm, s_fsm = _marker(tmp_path, "x9_fsm.sh")
    with (r_fsm / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write(f"[core]\n\tfsmonitor = {s_fsm}\n")
    cases.append((r_fsm, m_fsm, h_fsm, t_fsm))

    # 2. core.worktree
    r_wt = _init_repo(tmp_path, "h_wt")
    h_wt, t_wt = _git(r_wt, "rev-parse", "HEAD"), _git(r_wt, "rev-parse", "HEAD^{tree}")
    with (r_wt / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write(f"[core]\n\tworktree = {other}\n")
    cases.append((r_wt, None, h_wt, t_wt))

    # 3. extensions.objectformat
    r_ext = _init_repo(tmp_path, "h_ext")
    h_ext, t_ext = _git(r_ext, "rev-parse", "HEAD"), _git(r_ext, "rev-parse", "HEAD^{tree}")
    with (r_ext / ".git" / "config").open("a", encoding="utf-8") as fh:
        fh.write("[extensions]\n\tobjectformat = sha1\n")
    cases.append((r_ext, None, h_ext, t_ext))

    # 4. objects/info/alternates
    r_alt = _init_repo(tmp_path, "h_alt")
    h_alt, t_alt = _git(r_alt, "rev-parse", "HEAD"), _git(r_alt, "rev-parse", "HEAD^{tree}")
    (r_alt / ".git" / "objects" / "info").mkdir(parents=True, exist_ok=True)
    (r_alt / ".git" / "objects" / "info" / "alternates").write_text(str(other / ".git" / "objects") + "\n", encoding="utf-8")
    cases.append((r_alt, None, h_alt, t_alt))

    for repo, marker, head_sha, tree_sha in cases:
        before = _snapshot_target(repo)
        _assert_all_runners_refuse(repo, tmp_path, head_sha, tree_sha)
        if marker is not None:
            assert not marker.exists()
        _assert_x9_preserved(repo, before)
