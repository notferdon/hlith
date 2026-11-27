"""Build a tiny ordinary Git clone for the UI Running -> History -> Verdict journey.

All generated repositories and engine state live under the caller-supplied directory.
The source repository has a two-line uncommitted change and one stdlib unittest.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


BASE = {
    "calc.py": "def add(a, b):\n    return a + b\n",
    "test_calc.py": "import unittest\nfrom calc import add\n\n\nclass AddTests(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(1, 1), 2)\n\n\nif __name__ == \"__main__\":\n    unittest.main()\n",
}
CHANGED = {
    "calc.py": "def add(a, b):\n    return a + b + 1\n",
    "test_calc.py": "import unittest\nfrom calc import add\n\n\nclass AddTests(unittest.TestCase):\n    def test_add(self):\n        self.assertEqual(add(1, 1), 3)\n\n\nif __name__ == \"__main__\":\n    unittest.main()\n",
}


def _git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Hlith fixture",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "Hlith fixture",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    ).stdout


def _write_tree(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _has_symlink(path: Path) -> bool:
    for root, dirs, files in os.walk(path, followlinks=False):
        base = Path(root)
        if any((base / name).is_symlink() for name in [*dirs, *files]):
            return True
    return False


def prepare(parent: Path) -> tuple[Path, Path]:
    """Create the seed and ordinary clone; refuse to reuse an existing directory."""
    parent = Path(parent).resolve()
    if parent.exists() and any(parent.iterdir()):
        raise FileExistsError(f"fixture output directory is not empty: {parent}")
    parent.mkdir(parents=True, exist_ok=True)
    seed, repo = parent / "seed", parent / "project"
    seed.mkdir()
    _git(seed, "init", "-q", "-b", "main")
    _write_tree(seed, BASE)
    _git(seed, "add", "-A")
    _git(seed, "commit", "-q", "-m", "stdlib fixture base")
    subprocess.run(["git", "clone", "--quiet", "--no-hardlinks", str(seed), str(repo)], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not (repo / ".git").is_dir() or (repo / ".git").is_symlink() or _has_symlink(repo):
        raise RuntimeError("fixture is not a regular non-symlink Git clone")
    _write_tree(repo, CHANGED)
    diff = _git(repo, "diff", "--numstat").splitlines()
    if sorted(line.split("\t")[:2] for line in diff) != [["1", "1"], ["1", "1"]]:
        raise RuntimeError(f"expected exactly two changed lines in two files, got {diff!r}")
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    subprocess.run([sys.executable, "-B", "-m", "unittest"], cwd=repo, env=env, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if _has_symlink(repo):
        raise RuntimeError("fixture clone acquired a symlink")
    if _git(repo, "status", "--porcelain=v1", "-uall").count("\n") != 2:
        raise RuntimeError("fixture working tree is not exactly the two intended changed files")
    return seed, repo
