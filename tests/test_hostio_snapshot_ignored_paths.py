# SPDX-License-Identifier: Apache-2.0
"""Sealed post trees must preserve the literal tracked tree and patch result."""

from __future__ import annotations

import subprocess
from pathlib import Path

from hlith.hostio.snapshot import LocalSnapshotService
from hlith.obligation.facts import changed_files


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _repo(tmp_path: Path, *, ignore: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Hlith test")
    _git(repo, "config", "user.email", "hlith-test@example.invalid")

    files = {
        ".gitignore": ignore,
        ".circleci/config.yml": "version: 2\n",
        ".pre-commit-config.yaml": "repos: []\n",
        "pkg/m.py": "def value():\n    return 1\n",
        "src/globally-excluded.py": "VALUE = 1\n",
    }
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    # The real base tree already tracks files even when its own ignore rules
    # match them. Reconstructing that tree must preserve the same fact.
    _git(repo, "add", "-f", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _service(tmp_path: Path) -> LocalSnapshotService:
    return LocalSnapshotService(root=tmp_path / "snapshots")


def test_unchanged_tracked_dotfiles_are_not_touched_and_global_excludes_are_ignored(tmp_path, monkeypatch):
    global_excludes = tmp_path / "host-excludes"
    global_excludes.write_text("src/globally-excluded.py\n", encoding="utf-8")
    global_config = tmp_path / "host-gitconfig"
    global_config.write_text(
        f"[core]\n\texcludesFile = {global_excludes}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))

    repo = _repo(tmp_path, ignore=".*\nbuild/\n")
    base = _service(tmp_path).seal_base(repo)
    (repo / "pkg/m.py").write_text("def value():\n    return 2\n", encoding="utf-8")
    patch = _git(repo, "diff", "--binary")
    post = _service(tmp_path).reconstruct_post(base, patch)

    unchanged = (".gitignore", ".circleci/config.yml", ".pre-commit-config.yaml", "src/globally-excluded.py")
    for name in unchanged:
        assert (base.path / name).is_file(), name
        assert (post.path / name).is_file(), name
        assert (post.path / name).read_bytes() == (base.path / name).read_bytes(), name
    assert changed_files(base.path, post.path) == ("pkg/m.py",)


def test_changed_tracked_gitignore_is_present_and_reported(tmp_path):
    repo = _repo(tmp_path, ignore=".*\nbuild/\n")
    service = _service(tmp_path)
    base = service.seal_base(repo)
    (repo / ".gitignore").write_text("*.tmp\nbuild/\n", encoding="utf-8")
    patch = _git(repo, "diff", "--binary")

    post = service.reconstruct_post(base, patch)

    assert (post.path / ".gitignore").is_file()
    assert (post.path / ".gitignore").read_text(encoding="utf-8") == "*.tmp\nbuild/\n"
    assert changed_files(base.path, post.path) == (".gitignore",)


def test_new_files_matching_ignore_rules_are_in_the_post_tree_and_touched(tmp_path):
    repo = _repo(tmp_path, ignore=".*\nbuild/\n")
    service = _service(tmp_path)
    base = service.seal_base(repo)

    (repo / ".hidden.py").write_text("VALUE = 2\n", encoding="utf-8")
    (repo / "build/new.py").parent.mkdir(parents=True)
    (repo / "build/new.py").write_text("VALUE = 3\n", encoding="utf-8")
    _git(repo, "add", "-f", "--", ".hidden.py", "build/new.py")
    patch = _git(repo, "diff", "--cached", "--binary")

    post = service.reconstruct_post(base, patch)

    assert (post.path / ".hidden.py").read_text(encoding="utf-8") == "VALUE = 2\n"
    assert (post.path / "build/new.py").read_text(encoding="utf-8") == "VALUE = 3\n"
    assert changed_files(base.path, post.path) == (".hidden.py", "build/new.py")
