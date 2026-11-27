from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from hlith.agent import capture
from hlith.agent.capture import _diff_stage
from hlith.agent.tools import _measure


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
    ).stdout.strip()


def _repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "test")
    _git(repo, "config", "user.email", "test@example.invalid")
    (repo / ".gitignore").write_text(".*\n", encoding="utf-8")
    (repo / ".settings").write_text("before\n", encoding="utf-8")
    (repo / "calc.py").write_text("def f(): return 1\n", encoding="utf-8")
    _git(repo, "add", "-f", ".gitignore", ".settings", "calc.py")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def test_diff_stage_keeps_tracked_dotfile_changes_and_records_ignored_additions(tmp_path):
    repo = _repo(tmp_path)
    stage = tmp_path / "stage"
    shutil.copytree(repo, stage, ignore=shutil.ignore_patterns(".git"))
    baseline = _measure(stage)
    (stage / ".settings").write_text("after\n", encoding="utf-8")
    (stage / ".new-cache").write_text("operator-visible claim data\n", encoding="utf-8")
    after = _measure(stage)
    claimed = {path: digest for path, digest in after.items() if baseline.get(path) != digest}

    diff, touched, ignored, _flags, _observed = _diff_stage(repo, stage, tmp_path / "scratch")

    assert {".settings", ".new-cache"} <= set(claimed)
    assert ".settings" in touched
    assert "-before" in diff and "+after" in diff
    assert ".new-cache" in ignored
    assert ".new-cache" not in touched


def test_negative_control_empty_index_loses_the_tracked_dotfile_edit(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    stage = tmp_path / "stage"
    shutil.copytree(repo, stage, ignore=shutil.ignore_patterns(".git"))
    (stage / ".settings").write_text("after\n", encoding="utf-8")
    real_git = capture._git

    def without_read_tree(cwd, *args, **kwargs):
        if args[:2] == ("read-tree", "FETCH_HEAD"):
            return ""
        return real_git(cwd, *args, **kwargs)

    monkeypatch.setattr(capture, "_git", without_read_tree)
    diff, _touched, _ignored, _flags, _observed = _diff_stage(repo, stage, tmp_path / "scratch")

    assert "+after" not in diff
