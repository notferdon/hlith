# SPDX-License-Identifier: Apache-2.0
"""Clean export of a git revision: every tracked entry, no attributes honoured, nothing else.

`git archive` applies `.gitattributes` (`export-ignore`, `export-subst`), so a tracked file marked export-ignore is
missing from the stage; the diff then records it as deleted and the landed patch deletes it from the target
(finding 26). This exporter reads the tree object itself (`ls-tree` + `cat-file --batch`): no attributes, no
smudge/text conversion, symlinks as symlinks, executable bit kept, submodules refused."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


class ExportError(RuntimeError):
    """The revision cannot be exported cleanly (submodule, unsafe path, git failure)."""


def _git(repo: Path, *args: str, data: bytes | None = None) -> bytes:
    """Compatibility helper with a SINGLE permitted read-only ls-tree shape (canonical hostio.git_read runner)."""
    from .git_read import _run_ro
    from .integrity import HostIntegrityError
    if data is not None or tuple(args[:5]) != ("ls-tree", "-r", "-l", "-z", "--full-tree") or len(args) != 6:
        raise ExportError("unsupported tree-export Git operation")
    try:
        return _run_ro(repo, args)
    except HostIntegrityError as exc:
        raise ExportError("tree listing refused: " + str(exc)) from exc


MAX_BLOB_BYTES = 16 * 1024 * 1024   # per tracked blob (half of runtime.MAX_EFFECT_BYTES: the stage as a whole is capped at 32 MiB)
MAX_TOTAL_BYTES = 256 * 1024 * 1024  # all blobs of one export
MAX_ENTRIES = 200_000
_BAD_NAME_CHARS = frozenset("\n\r\0\\")


def _unsafe_component(p: str) -> bool:
    return p in ("", ".", "..") or p.casefold() == ".git"


def _safe_parent(dest: Path, rel: str) -> Path:
    parts = rel.split("/")
    if any(c in _BAD_NAME_CHARS for c in rel) or any(_unsafe_component(p) for p in parts):
        raise ExportError(f"unsafe path in tree: {rel!r}")
    cur = dest
    for p in parts[:-1]:
        cur = cur / p
        if os.path.islink(cur):
            raise ExportError(f"tree path goes through a symlink: {rel!r}")
        cur.mkdir(exist_ok=True)
    return cur / parts[-1]


def _check_symlink(rel: str, link: str) -> None:
    """Keep only relative links that stay inside the export root and never point into .git."""
    import posixpath
    bad = (not link or any(c in link for c in "\0\\") or link.startswith("/"))
    if not bad:
        norm = posixpath.normpath(posixpath.join(posixpath.dirname(rel), link))
        bad = norm == ".." or norm.startswith("../") or norm == "." or any(c.casefold() == ".git" for c in norm.split("/"))
    if bad:
        raise ExportError(f"unsafe symlink {rel!r} -> {link!r}: its target is absolute, escapes the export root or points into .git")


def export_tree(repo: Path, rev: str, dest: Path) -> Path:
    """Clean export of ``rev``'s tree into a NEW directory ``dest`` (no export-ignore filtering). ONE implementation: the
    canonical hostio.git_read.HardenedGitRead.export_tree (bounds, symlink and hostile-name policy, hostile-repo refusal);
    this wrapper only resolves ``rev`` to a tree oid and keeps the legacy ExportError type."""
    from ..contract.identities import tree_oid
    from .git_read import HardenedGitRead, _run_ro
    from .integrity import HostIntegrityError
    try:
        resolved = _run_ro(repo, ("rev-parse", "--verify", f"{rev}^{{tree}}")).decode("ascii").strip()
        HardenedGitRead().export_tree(Path(repo), tree_oid(resolved), Path(dest))
    except (HostIntegrityError, ValueError, UnicodeError) as exc:
        raise ExportError("tree export refused: " + str(exc)) from exc
    return Path(dest)
