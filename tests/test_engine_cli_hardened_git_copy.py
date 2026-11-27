"""P1 (maintainer/IDE, rcfinal-20261120-1767b4a4): engine_cli's own git reads (apply review, --expect-head, hosted-agent scope) ran plain
``git -C repo ...`` with the inherited environment and the repository's config, so an enabled core.fsmonitor RAN during a read-only
apply review. They now go through hostio.git_read.safe_git_read: vet the repository, scrubbed GIT_* environment, hardening flags."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from hlith.operator.engine_cli import _safe_git
from hlith.runtime import RuntimeBoundary


def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "a.py").write_text("x = 1\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    return repo


def _marker(tmp_path: Path, name: str) -> Path:
    script = tmp_path / name
    script.write_text('#!/bin/sh\necho fired > "$0.fired"\nexit 0\n')
    script.chmod(0o755)
    return script


def test_a_clean_repository_reads_normally(tmp_path):
    repo = _repo(tmp_path)
    assert len(_safe_git(repo, "rev-parse", "HEAD")) == 40
    assert _safe_git(repo, "status", "--porcelain=v1", "--untracked-files=no") == ""


def test_a_repository_config_that_runs_a_program_is_refused_and_never_runs(tmp_path):
    repo = _repo(tmp_path)
    script = _marker(tmp_path, "mark-cfg.sh")
    _git(repo, "config", "core.fsmonitor", str(script))
    with pytest.raises(RuntimeBoundary, match="core.fsmonitor|refused"):
        _safe_git(repo, "status", "--porcelain=v1", "--untracked-files=no")
    assert not Path(str(script) + ".fired").exists()


def test_fsmonitor_injected_through_the_inherited_environment_never_runs(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    script = _marker(tmp_path, "mark-env.sh")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", str(script))
    assert _safe_git(repo, "status", "--porcelain=v1", "--untracked-files=no") == ""  # the environment is scrubbed, not trusted
    assert not Path(str(script) + ".fired").exists()


def test_inherited_git_dir_cannot_redirect_the_read_to_another_repository(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(other)], check=True)
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    assert len(_safe_git(repo, "rev-parse", "HEAD")) == 40  # the repository asked for, not the one GIT_DIR names


# ---- IDE P1 on db8a5bb6: a repository's own core.worktree must not move a hardened read to a different directory --------------------------

def _redirected(tmp_path: Path) -> tuple[Path, Path]:
    repo = _repo(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "unrelated.txt").write_text("not the repository\n")
    _git(repo, "config", "core.worktree", str(elsewhere))
    return repo, elsewhere


def test_core_worktree_is_named_and_refused_by_the_vet(tmp_path):
    from hlith.hostio.git_read import HardenedGitRead

    repo, _ = _redirected(tmp_path)
    reason = HardenedGitRead().repository_hostile_reason(repo)  # the vet names the offending key (exact wording is not part of the contract)
    assert reason is not None and "core.worktree" in reason.lower(), reason
    with pytest.raises(RuntimeBoundary, match="core.worktree"):
        _safe_git(repo, "status", "--porcelain=v1", "--untracked-files=no")


def test_the_tui_refusal_and_the_gate_vet_share_the_same_matcher(tmp_path):
    """gitq.refusal() (the TUI's early readable refusal) reads the same _EXEC_KEYS, so every entry point rejects the redirected config;
    a clean repository is the control (nothing refused, normal reads)."""
    from hlith.operator import gitq

    repo, _ = _redirected(tmp_path)
    reason = gitq.refusal(repo)
    assert reason is not None and "core.worktree" in reason
    (tmp_path / "clean").mkdir()
    clean = _repo(tmp_path / "clean")
    assert gitq.refusal(clean) is None
    assert len(_safe_git(clean, "rev-parse", "HEAD")) == 40


def test_even_without_the_vet_the_read_stays_in_the_real_work_tree(tmp_path):
    """_run_ro now vets every call, so the runner alone is no longer reachable: prove the --work-tree/--git-dir pinning on the argv builder and
    run that argv through the spawn seam directly (a repository changed between the vet and the command)."""
    from hlith.hostio.git_read import _spawn, readonly_argv, scrubbed_git_env

    repo, elsewhere = _redirected(tmp_path)
    real = str(repo.resolve())
    env = scrubbed_git_env(repo.resolve().parent)

    def run(argv):
        cp = _spawn(argv, env=env)
        assert cp.returncode == 0, cp.stderr
        return cp.stdout.decode().strip()

    argv = readonly_argv(repo, ("rev-parse", "--show-toplevel"))
    assert argv[argv.index("--work-tree") + 1] == real and argv[argv.index("--git-dir") + 1] == real + "/.git"
    assert run(argv) == real
    assert run(readonly_argv(repo, ("status", "--porcelain=v1", "--untracked-files=no"))) == ""  # a.py is NOT reported deleted
    # negative control: without the explicit pin the repository's own core.worktree DOES move the read (the fixture is hostile)
    i = argv.index("--work-tree")
    unpinned = argv[:i] + argv[i + 2:]
    assert run(unpinned) == str(elsewhere.resolve())
