# SPDX-License-Identifier: Apache-2.0
"""review focused tests for LocalSnapshotService lifecycle, fail/cancel cleanup, symlinks, read-only trees, and G2 recovery."""

from __future__ import annotations

import gc
import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.gate.api import LocalGateService
from hlith.gate.git_write import compute_path_images, head_commit
from hlith.gate.journal import begin_journal
from hlith.hostio.integrity import HostIntegrityError, capture_target_identity
from hlith.hostio.snapshot import LocalSnapshotService
from hlith.hostio.state import LocalHostState


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _init_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Hlith Test")
    _git(repo, "config", "user.email", "n4@example.invalid")
    (repo / "pkg").mkdir(exist_ok=True)
    (repo / "pkg" / "m.py").write_text("def f(x):\n    return x\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _repo_fingerprint(repo: Path) -> tuple[str, tuple[tuple[str, str, bytes], ...]]:
    head = _git(repo, "rev-parse", "HEAD").decode("ascii").strip()
    items: list[tuple[str, str, bytes]] = []
    for root, dirs, files in os.walk(repo, followlinks=False):
        dirs.sort()
        files.sort()
        for entry_list, kind in ((dirs, "dir"), (files, "file")):
            for name in entry_list:
                p = Path(root) / name
                rel = p.relative_to(repo).as_posix()
                if os.path.islink(p):
                    items.append((rel, "link", os.readlink(p).encode("utf-8", "surrogateescape")))
                elif kind == "dir":
                    items.append((rel, "dir", b""))
                else:
                    digest = hashlib.sha256(p.read_bytes()).hexdigest().encode("ascii")
                    items.append((rel, "file", digest))
    return head, tuple(items)


def _snap_entries(root: Path) -> list[str]:
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir())


def test_positive_lifecycle_release_and_idempotent_close(tmp_path: Path):
    repo = _init_repo(tmp_path)
    (repo / "pkg" / "m.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
    patch = _git(repo, "diff", "--binary")
    _git(repo, "checkout", "-q", "--", "pkg/m.py")

    snap_root = tmp_path / "snaps"
    before = _repo_fingerprint(repo)

    svc = LocalSnapshotService(root=snap_root, cleanup_on_exit=False)
    base = svc.seal_base(repo)
    assert (base.path / "pkg" / "m.py").read_text(encoding="utf-8") == "def f(x):\n    return x\n"

    post = svc.reconstruct_post(base, patch)
    assert (post.path / "pkg" / "m.py").read_text(encoding="utf-8") == "def f(x):\n    return x + 1\n"
    assert len(svc.owned_dirs()) == 2
    assert len(_snap_entries(snap_root)) == 2

    assert svc.release(base) is True
    assert svc.release(base) is False
    assert not base.path.exists()
    assert len(svc.owned_dirs()) == 1
    assert len(_snap_entries(snap_root)) == 1

    svc.close()
    svc.close()
    assert svc.owned_dirs() == ()
    assert _snap_entries(snap_root) == []
    assert _repo_fingerprint(repo) == before


def test_context_manager_cleans_up_on_normal_and_exception_exit(tmp_path: Path):
    repo = _init_repo(tmp_path)
    snap_root = tmp_path / "snaps"

    with LocalSnapshotService(root=snap_root, cleanup_on_exit=False) as svc:
        base = svc.seal_base(repo)
        assert base.path.is_dir()
    assert _snap_entries(snap_root) == []

    with pytest.raises(RuntimeError, match="boom"):
        with LocalSnapshotService(root=snap_root, cleanup_on_exit=False) as svc:
            svc.seal_base(repo)
            raise RuntimeError("boom")
    assert _snap_entries(snap_root) == []


def test_back_compat_drop_service_and_snapshot_keeps_path_alive_until_exit(tmp_path: Path):
    repo = _init_repo(tmp_path)
    snap_root = tmp_path / "snaps"
    dest = LocalSnapshotService(root=snap_root, cleanup_on_exit=False).seal_base(repo).path
    gc.collect()
    assert (dest / "pkg" / "m.py").is_file()
    # Explicit path-based release works on a fresh service? No, release targets owned dirs; manual cleanup in tmp_path.


def test_seal_base_failure_and_cancel_do_not_leak_and_target_unchanged(tmp_path: Path):
    repo = _init_repo(tmp_path)
    snap_root = tmp_path / "snaps"
    before = _repo_fingerprint(repo)

    class _ExplodingGitRead:
        def repository_hostile_reason(self, r):
            return None

        def head_tree(self, r):
            return "a" * 40

        def export_tree(self, r, oid, dest):
            dest.mkdir(parents=True, exist_ok=True)
            (dest / "partial").write_bytes(b"partial")
            raise RuntimeError("export failed")

    svc = LocalSnapshotService(git_read=_ExplodingGitRead(), root=snap_root, cleanup_on_exit=False)
    with pytest.raises(RuntimeError, match="export failed"):
        svc.seal_base(repo)
    assert svc.owned_dirs() == ()
    assert _snap_entries(snap_root) == []

    class _CancelledGitRead(_ExplodingGitRead):
        def export_tree(self, r, oid, dest):
            dest.mkdir(parents=True, exist_ok=True)
            raise KeyboardInterrupt()

    svc_cancel = LocalSnapshotService(git_read=_CancelledGitRead(), root=snap_root, cleanup_on_exit=False)
    with pytest.raises(KeyboardInterrupt):
        svc_cancel.seal_base(repo)
    assert svc_cancel.owned_dirs() == ()
    assert _snap_entries(snap_root) == []
    assert _repo_fingerprint(repo) == before


def test_seal_base_hostile_target_refuses_with_no_marker_no_temp_dirs(tmp_path: Path):
    repo = _init_repo(tmp_path)
    snap_root = tmp_path / "snaps"
    marker = tmp_path / "pwned.marker"
    _git(repo, "config", "core.fsmonitor", f"touch {marker}")
    before = _repo_fingerprint(repo)

    svc = LocalSnapshotService(root=snap_root, cleanup_on_exit=False)
    with pytest.raises(HostIntegrityError, match="hostile"):
        svc.seal_base(repo)
    assert not marker.exists()
    assert svc.owned_dirs() == ()
    assert _snap_entries(snap_root) == []
    assert _repo_fingerprint(repo) == before


@pytest.mark.parametrize("kind", ["non_applying_patch", "cancel", "export_error", "patch_violation"])
def test_reconstruct_post_error_and_cancel_clean_up_work_and_scratch(tmp_path: Path, monkeypatch, kind: str):
    repo = _init_repo(tmp_path)
    snap_root = tmp_path / "snaps"
    svc = LocalSnapshotService(root=snap_root, cleanup_on_exit=False)
    base = svc.seal_base(repo)
    base_dir_count = len(_snap_entries(snap_root))

    (repo / "pkg" / "m.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
    good_patch = _git(repo, "diff", "--binary")
    _git(repo, "checkout", "-q", "--", "pkg/m.py")

    if kind == "non_applying_patch":
        patch = good_patch.replace(b"-    return x", b"-    return 999")
        with pytest.raises(HostIntegrityError, match="apply"):
            svc.reconstruct_post(base, patch)
    elif kind == "patch_violation":
        bad_patch = (
            b"diff --git a/.git/config b/.git/config\n"
            b"new file mode 100644\n"
            b"--- /dev/null\n"
            b"+++ b/.git/config\n"
            b"@@ -0,0 +1 @@\n+[core]\n"
        )
        with pytest.raises(HostIntegrityError, match="patch-policy-violation"):
            svc.reconstruct_post(base, bad_patch)
    elif kind == "cancel":
        from hlith.hostio import snapshot as snap_mod

        orig_run = snap_mod._run_scratch_git

        def _cancel_on_apply(r, c, args, *, input_bytes=None):
            if args and args[0] == "apply":
                raise KeyboardInterrupt()
            return orig_run(r, c, args, input_bytes=input_bytes)

        monkeypatch.setattr(snap_mod, "_run_scratch_git", _cancel_on_apply)
        with pytest.raises(KeyboardInterrupt):
            svc.reconstruct_post(base, good_patch)
    elif kind == "export_error":
        def _boom(r, oid, dest):
            dest.mkdir(parents=True, exist_ok=True)
            raise RuntimeError("post export failed")

        monkeypatch.setattr(svc._git_read, "export_tree", _boom)
        with pytest.raises(RuntimeError, match="post export failed"):
            svc.reconstruct_post(base, good_patch)

    # Only the base snapshot dir remains; zero leaked hlith-post-* dirs.
    entries = _snap_entries(snap_root)
    assert len(entries) == base_dir_count
    assert not any(e.startswith("hlith-post-") for e in entries)
    svc.close()
    assert _snap_entries(snap_root) == []


@pytest.mark.parametrize("hazard", ["fifo", "escape_symlink", "hlith_symlink"])
def test_reconstruct_post_rejects_special_file_or_unsafe_symlink_without_leak(tmp_path: Path, hazard: str):
    repo = _init_repo(tmp_path)
    snap_root = tmp_path / "snaps"
    svc = LocalSnapshotService(root=snap_root, cleanup_on_exit=False)
    base = svc.seal_base(repo)

    if hazard == "fifo":
        os.mkfifo(base.path / "bad.fifo")
    elif hazard == "escape_symlink":
        os.symlink("../outside", base.path / "bad_link")
    elif hazard == "hlith_symlink":
        os.symlink(".hlith/secret", base.path / "hlith_link")

    with pytest.raises(HostIntegrityError):
        svc.reconstruct_post(base, b"")

    entries = _snap_entries(snap_root)
    assert not any(e.startswith("hlith-post-") for e in entries)
    svc.close()
    assert _snap_entries(snap_root) == []


def test_readonly_target_and_readonly_snapshot_cleanup(tmp_path: Path):
    repo = _init_repo(tmp_path)
    snap_root = tmp_path / "snaps"
    ro_paths: list[Path] = []
    try:
        for p in repo.rglob("*"):
            if not p.is_symlink():
                ro_paths.append(p)
        for p in reversed(ro_paths):
            if p.is_file():
                os.chmod(p, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        for p in reversed(ro_paths):
            if p.is_dir():
                os.chmod(p, stat.S_IRUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP)

        svc = LocalSnapshotService(root=snap_root, cleanup_on_exit=False)
        snap = svc.seal_base(repo)
        assert (snap.path / "pkg" / "m.py").is_file()

        # Simulate read-only permissions inside snapshot tree too, then prove close() still removes it.
        ro_file = snap.path / "pkg" / "m.py"
        ro_dir = snap.path / "pkg"
        os.chmod(ro_file, 0o444)
        os.chmod(ro_dir, 0o555)
        svc.close()
        assert _snap_entries(snap_root) == []
    finally:
        for p in ro_paths:
            try:
                if p.is_dir():
                    os.chmod(p, 0o755)
                elif p.exists():
                    os.chmod(p, 0o644)
            except OSError:
                pass


def test_atexit_safety_net_cleans_unclosed_service_on_process_exit(tmp_path: Path):
    repo = _init_repo(tmp_path)
    snap_root = tmp_path / "snaps"
    script = (
        "from pathlib import Path\n"
        "from hlith.hostio.snapshot import LocalSnapshotService\n"
        f"repo = Path({str(repo)!r})\n"
        f"root = Path({str(snap_root)!r})\n"
        "svc = LocalSnapshotService(root=root)\n"
        "base = svc.seal_base(repo)\n"
        "post = svc.reconstruct_post(base, b'')\n"
        "assert base.path.is_dir() and post.path.is_dir()\n"
    )
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    cp = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True, check=False)
    assert cp.returncode == 0, cp.stderr
    assert _snap_entries(snap_root) == []


def _worktree_fingerprint(repo: Path) -> tuple[str, tuple[tuple[str, str, bytes], ...]]:
    head = _git(repo, "rev-parse", "HEAD").decode("ascii").strip()
    items: list[tuple[str, str, bytes]] = []
    for root, dirs, files in os.walk(repo, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != ".git")
        files.sort()
        for entry_list, kind in ((dirs, "dir"), (files, "file")):
            for name in entry_list:
                p = Path(root) / name
                rel = p.relative_to(repo).as_posix()
                if os.path.islink(p):
                    items.append((rel, "link", os.readlink(p).encode("utf-8", "surrogateescape")))
                elif kind == "dir":
                    items.append((rel, "dir", b""))
                else:
                    digest = hashlib.sha256(p.read_bytes()).hexdigest().encode("ascii")
                    items.append((rel, "file", digest))
    return head, tuple(items)


def test_gate_journal_crash_recovery_restores_target_cleanly(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _init_repo(tmp_path)
    (repo / "pkg" / "m.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")
    patch = _git(repo, "diff", "--binary")
    _git(repo, "checkout", "-q", "--", "pkg/m.py")

    before_wt = _worktree_fingerprint(repo)
    base_head = head_commit(repo)

    host = LocalHostState(tmp_path / "state")
    gate = LocalGateService(host, snapshot_service=LocalSnapshotService(root=tmp_path / "snaps", cleanup_on_exit=False))
    repo_ident = host.stable_repo_identity(repo)
    images = compute_path_images(repo, base_head, patch, ["pkg/m.py"])
    begin_journal(
        repo,
        host,
        repo_ident,
        base_head=base_head,
        paths=["pkg/m.py"],
        patch_sha256="a" * 64,
        images=images,
        post_tree="b" * 40,
    )
    # Simulate crash after applying post-image to worktree before commit/clear_journal.
    (repo / "pkg" / "m.py").write_text("def f(x):\n    return x + 1\n", encoding="utf-8")

    status = gate.recover(repo)
    assert status == f"recovered:{base_head[:12]}"
    assert _worktree_fingerprint(repo) == before_wt
    assert _git(repo, "status", "--porcelain") == b""
    assert gate.recover(repo) == "clean"
