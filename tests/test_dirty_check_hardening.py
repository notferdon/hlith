"""review's G2-dirtycheck-attack (hlith/review-acceptance 0e1d10f): the dirty-repo pre-check I added in 46109fb ran a plain `git status --porcelain` on the UNTRUSTED --repo as the first
step of `hlith run`, with the caller's environment. D1 core.fsmonitor in .git/config was executed; D2 a clean filter + .gitattributes on a modified file was executed; D3 the caller's
GIT_DIR/GIT_WORK_TREE were inherited, so a VICTIM repository was judged. The check must use the gate's own hardened git and run the gate's executable-config / attribute scan first."""
import os
import subprocess
from pathlib import Path

from hlith import cli


def _git(repo, *a, env=None):
    base = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid"}
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, env=env or base)


def _repo(tmp_path, name="r"):
    r = tmp_path / name
    r.mkdir()
    (r / "a.py").write_text("x = 1\n")
    _git(r, "init", "-q", "-b", "main")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _marker_script(tmp_path):
    marker = tmp_path / "EXECUTED"
    script = tmp_path / "hook.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\ncat\n")
    script.chmod(0o755)
    return marker, script


def test_d1_core_fsmonitor_in_the_repo_config_is_never_executed(tmp_path):
    marker, script = _marker_script(tmp_path)
    r = _repo(tmp_path)
    _git(r, "config", "core.fsmonitor", str(script))
    (r / "a.py").write_text("x = 2\n")  # dirty, so a status really runs
    cli.dirty_repo_reason(r)
    assert not marker.exists(), "the repository's fsmonitor program was executed by the dirty check"


def test_d2_clean_filter_with_gitattributes_on_a_modified_file_is_never_executed(tmp_path):
    marker, script = _marker_script(tmp_path)
    r = _repo(tmp_path)
    (r / ".gitattributes").write_text("*.py filter=evil\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "attrs")
    _git(r, "config", "filter.evil.clean", str(script))
    (r / "a.py").write_text("x = 3\n")
    cli.dirty_repo_reason(r)
    assert not marker.exists(), "the repository's clean filter was executed by the dirty check"


def test_d3_the_callers_git_dir_and_work_tree_do_not_redirect_the_check(tmp_path, monkeypatch):
    victim = _repo(tmp_path, "victim")
    (victim / "a.py").write_text("victim dirty\n")
    target = _repo(tmp_path, "target")  # CLEAN
    monkeypatch.setenv("GIT_DIR", str(victim / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(victim))
    assert cli.dirty_repo_reason(target) is None, "the check judged the caller's GIT_DIR repository, not the target"
    (target / "a.py").write_text("target dirty\n")
    why = cli.dirty_repo_reason(target)
    assert why and "a.py" in why and "1 path(s)" in why


def test_the_hardened_check_still_reports_a_normal_dirty_and_a_clean_repository(tmp_path):
    r = _repo(tmp_path)
    assert cli.dirty_repo_reason(r) is None
    (r / "new.txt").write_text("x\n")
    (r / "a.py").write_text("changed\n")
    why = cli.dirty_repo_reason(r)
    assert why and "2 path(s)" in why and "commit or stash" in why and "clean clone" in why


def test_a_repository_the_gate_would_refuse_is_not_inspected_at_all(tmp_path):
    """linked worktrees / submodule-style .git files are outside the gate's identity model: no git is run on them, the gate's own refusal owns the message."""
    r = _repo(tmp_path)
    wt = tmp_path / "wt"
    _git(r, "worktree", "add", "-q", str(wt))
    (wt / "a.py").write_text("dirty in a linked worktree\n")
    assert cli.dirty_repo_reason(wt) is None
