# SPDX-License-Identifier: Apache-2.0
"""One-line build identity for the operator surface. One source, never invented:
A Git source archive embeds its commit. Otherwise:
1. PINNED_RC.txt beside src/ (an installed, pinned candidate): its TAG (which carries the short commit);
2. else the short commit read from the checkout's plain `.git` directory (a plain clone; nothing is spawned);
3. else the literal 'dev build'."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_ARCHIVE_COMMIT = "$Format:%H$"  # substituted by git archive, retained in sdists and wheels
_TAG = re.compile(r"^TAG=([A-Za-z0-9._-]{1,64})\s*$", re.M)
_SHA40 = re.compile(r"[0-9a-f]{40}")
_REF = re.compile(r"refs/[A-Za-z0-9._/-]{1,200}")


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _head_commit(git_dir: Path) -> str | None:
    """The full commit of HEAD read straight from a plain `.git` DIRECTORY (no process is spawned: git stays behind hostio/git_read.py).
    A `.git` file (linked worktree), an unreadable or odd HEAD, or anything that is not exactly 40 hex yields None."""
    if git_dir.is_symlink() or not git_dir.is_dir():
        return None
    head = _read(git_dir / "HEAD").strip()
    if _SHA40.fullmatch(head):
        return head  # detached HEAD
    if not head.startswith("ref: "):
        return None
    ref = head[5:].strip()
    if not _REF.fullmatch(ref) or ".." in ref or "//" in ref or ref.endswith("/") or ref.endswith(".lock"):
        return None
    loose = _read(git_dir / ref).strip()
    if _SHA40.fullmatch(loose):
        return loose
    for line in _read(git_dir / "packed-refs").splitlines():
        sha, _, name = line.partition(" ")
        if name.strip() == ref and _SHA40.fullmatch(sha):
            return sha
    return None


def _compute(root: Path) -> str:
    try:
        pinned = (root / "PINNED_RC.txt").read_text(encoding="utf-8", errors="replace")
    except OSError:
        pinned = ""
    found = _TAG.search(pinned)
    if found:
        return found.group(1)
    commit = _head_commit(root / ".git")
    if commit:
        return commit[:8]
    return "dev build"


@lru_cache(maxsize=8)
def _cached(root: str) -> str:
    return _compute(Path(root))


def build_identity(root: Path | None = None) -> str:
    """The identity of the tree rooted at `root` (default: the tree this module was imported from)."""
    if root is None and _SHA40.fullmatch(_ARCHIVE_COMMIT):
        return _ARCHIVE_COMMIT[:8]
    return _cached(str(root if root is not None else Path(__file__).resolve().parents[3]))
