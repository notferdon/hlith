# SPDX-License-Identifier: Apache-2.0
"""L4 gate-private Git write operations (apply --index, commit, verified rollback).

Imports only ``contract`` and ``hostio`` primitives. Never exposed outside ``hlith.gate``.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

from ..contract.identities import TreeOid, tree_oid
from ..hostio.git_read import TIMEOUT, readonly_argv, scrubbed_git_env, vet_repository
from ..hostio.integrity import HostIntegrityError

_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_ID_CONFIG = ("-c", "user.name=hlith", "-c", "user.email=hlith@invalid.local")


def run_target_git(
    target: Path,
    args: tuple[str, ...],
    *,
    input_bytes: bytes | None = None,
    index_file: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run an internal L4 gate Git command against ``target`` with full hardening."""
    real = Path(target).resolve()
    violation = vet_repository(real)  # closed-world and fail-closed (the writer used to vet only the .git shape): no command runs on a repository that could not be proven safe
    if violation is not None:
        raise HostIntegrityError(f"gate: refusing target ({violation})")
    env = scrubbed_git_env(None, {"GIT_INDEX_FILE": index_file} if index_file is not None else None, writer=True)
    try:
        return subprocess.run(readonly_argv(real, args), input=input_bytes, capture_output=True, env=env, check=False, timeout=TIMEOUT * 10)
    except subprocess.TimeoutExpired:
        raise HostIntegrityError("gate: git timed out") from None
    except OSError as exc:  # e.g. E2BIG when a patch touches more paths than argv can carry: a gate error, never a raw crash
        raise HostIntegrityError(f"gate: cannot run git ({exc.strerror or exc})") from None


def head_commit(target: Path) -> str:
    cp = run_target_git(target, ("rev-parse", "--verify", "HEAD"))
    if cp.returncode != 0:
        raise HostIntegrityError("gate: cannot resolve HEAD")
    oid = cp.stdout.decode("ascii").strip()
    if not _HEX40.fullmatch(oid):
        raise HostIntegrityError(f"gate: invalid HEAD oid {oid!r}")
    return oid


def head_landing_keys(target: Path) -> tuple[str, ...]:
    cp = run_target_git(
        target,
        ("log", "-1", "--format=%(trailers:key=Hlith-Key,valueonly,separator=%x2C)"),
    )
    if cp.returncode != 0:
        raise HostIntegrityError("gate: cannot read the landing keys of HEAD")  # never "no keys" (that would re-land)
    raw = cp.stdout.decode("utf-8", "replace").strip()
    return tuple(k.strip() for k in raw.split(",") if k.strip())


def changed_paths_between_snapshots(base_dir: Path, post_dir: Path) -> tuple[str, ...]:
    """Return relative paths changed between two exported snapshot directories."""
    def _files(root: Path) -> dict[str, bytes]:
        out: dict[str, bytes] = {}
        for p in sorted(root.rglob("*")):
            if p.is_symlink():
                out[p.relative_to(root).as_posix()] = b"SYMLINK:" + os.readlink(p).encode("utf-8", "replace")
            elif p.is_file():
                out[p.relative_to(root).as_posix()] = p.read_bytes()
        return out

    base_files = _files(base_dir)
    post_files = _files(post_dir)
    changed = [
        rel for rel in sorted(set(base_files) | set(post_files))
        if base_files.get(rel) != post_files.get(rel)
    ]
    return tuple(changed)


def patch_paths(target: Path, patch: bytes) -> list[str]:
    """Extract touched paths from ``patch`` using ``git apply --numstat -z``."""
    if not patch.strip():
        return []
    cp = run_target_git(target, ("apply", "--numstat", "-z", "-"), input_bytes=patch)
    if cp.returncode != 0:
        err = cp.stderr.decode("utf-8", "replace").strip()[:300]
        raise HostIntegrityError(f"gate: invalid patch ({err})")
    paths: list[str] = []
    tokens = cp.stdout.split(b"\0")
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if not tok:
            i += 1
            continue
        parts = tok.split(b"\t", 2)
        if len(parts) == 3:
            if parts[2]:
                paths.append(parts[2].decode("utf-8", "surrogateescape"))
                i += 1
            else:
                # rename: next two NUL-terminated tokens are old and new paths
                if i + 2 < len(tokens):
                    old_p = tokens[i + 1].decode("utf-8", "surrogateescape")
                    new_p = tokens[i + 2].decode("utf-8", "surrogateescape")
                    paths.extend([old_p, new_p])
                    i += 3
                else:
                    raise HostIntegrityError("gate: malformed numstat record (rename without both paths)")
        else:
            raise HostIntegrityError("gate: malformed numstat record")
    return sorted(set(p for p in paths if p))


def compute_path_images(target: Path, base_head: str, patch: bytes, paths: list[str]) -> dict[str, list[str]]:
    """Compute ``{path: [pre_blob, post_blob]}`` using a temporary index before touching ``target``."""
    if not paths:
        return {}
    pre: dict[str, str] = {}
    cp = run_target_git(target, ("ls-tree", "-z", base_head, "--", *paths))
    if cp.returncode != 0:
        raise HostIntegrityError("gate: ls-tree failed during path image capture")
    for rec in cp.stdout.split(b"\0"):
        if b"\t" in rec:
            meta, name = rec.split(b"\t", 1)
            pre[name.decode("utf-8", "surrogateescape")] = meta.decode("ascii").split()[2]
    post: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="hlith-gate-img-") as tmp:
        idx = str(Path(tmp) / "index")
        if run_target_git(target, ("read-tree", base_head), index_file=idx).returncode != 0:
            raise HostIntegrityError("gate: temp index read-tree failed")
        if patch.strip():
            if run_target_git(target, ("apply", "--cached", "-"), input_bytes=patch, index_file=idx).returncode != 0:
                raise HostIntegrityError("gate: patch does not apply cleanly to temp index")
        ls = run_target_git(target, ("ls-files", "-s", "-z", "--", *paths), index_file=idx)
        if ls.returncode != 0:
            raise HostIntegrityError("gate: temp index ls-files failed")
        for rec in ls.stdout.split(b"\0"):
            if b"\t" in rec:
                meta, name = rec.split(b"\t", 1)
                post[name.decode("utf-8", "surrogateescape")] = meta.decode("ascii").split()[1]
    return {p: [pre.get(p, ""), post.get(p, "")] for p in paths}


def worktree_blob_oid(target: Path, rel: str) -> str:
    full = Path(target) / rel
    if not full.exists() and not full.is_symlink():
        return ""
    if full.is_symlink():
        link = os.readlink(full).encode("utf-8", "surrogateescape")
        cp = run_target_git(target, ("hash-object", "--stdin"), input_bytes=link)
    elif full.is_file():
        cp = run_target_git(target, ("hash-object", "--no-filters", "--", rel))
    else:
        raise HostIntegrityError(f"gate: unsupported worktree entry {rel!r}")
    if cp.returncode != 0:
        raise HostIntegrityError(f"gate: cannot hash worktree path {rel!r}")
    return cp.stdout.decode("ascii").strip()


class PatchDoesNotApply(HostIntegrityError):
    """``git apply --check`` refused the patch BEFORE anything was written: there is nothing to roll back (the worktree content is the operator's own)."""


def apply_index_and_verify_tree(target: Path, patch: bytes, expected_post_tree: TreeOid) -> bool:
    """Apply ``patch`` with ``git apply --index`` and verify ``write-tree == expected_post_tree``."""
    if patch.strip():
        chk = run_target_git(target, ("apply", "--check", "-"), input_bytes=patch)
        if chk.returncode != 0:
            err = chk.stderr.decode("utf-8", "replace").strip()[:300]
            raise PatchDoesNotApply(f"gate: apply --check failed ({err})")
        ap = run_target_git(target, ("apply", "--index", "-"), input_bytes=patch)
        if ap.returncode != 0:
            err = ap.stderr.decode("utf-8", "replace").strip()[:300]
            raise HostIntegrityError(f"gate: apply --index failed ({err})")
    wt = run_target_git(target, ("write-tree",))
    if wt.returncode != 0:
        raise HostIntegrityError("gate: git write-tree failed after apply")
    staged_oid = tree_oid(wt.stdout.decode("ascii").strip())
    return staged_oid == expected_post_tree


def commit_staged(target: Path, message: str) -> str:
    cp = run_target_git(target, (*_ID_CONFIG, "commit", "-q", "--no-verify", "--allow-empty", "-m", message))
    if cp.returncode != 0:
        err = cp.stderr.decode("utf-8", "replace").strip()[:300]
        raise HostIntegrityError(f"gate: commit failed ({err})")
    return head_commit(target)


class HeadMovedError(HostIntegrityError):
    """HEAD is no longer the base this landing verified against: another writer landed in between (CAS refused)."""


def commit_tree_cas(target: Path, tree: str, parent: str, message: str) -> str:
    """Commit EXACTLY ``tree`` (the verified post tree) on ``parent`` and move HEAD only if it still is ``parent``.

    ``git commit`` would commit whatever the index holds when it runs; a concurrent writer can stage into the index after the gate's
    write-tree check. ``commit-tree`` takes the verified tree object itself, and ``update-ref HEAD <new> <old>`` is a compare-and-swap:
    it refuses when HEAD moved, so another writer's commit is never overwritten or reverted. Returns the new commit oid."""
    if not _HEX40.fullmatch(tree) or not _HEX40.fullmatch(parent):
        raise HostIntegrityError("gate: commit-tree needs full object ids")
    cp = run_target_git(target, (*_ID_CONFIG, "commit-tree", tree, "-p", parent, "-m", message))
    if cp.returncode != 0:
        raise HostIntegrityError(f"gate: commit-tree failed ({cp.stderr.decode('utf-8', 'replace').strip()[:300]})")
    new = cp.stdout.decode("ascii", "replace").strip()
    if not _HEX40.fullmatch(new):
        raise HostIntegrityError(f"gate: invalid commit oid {new!r}")
    up = run_target_git(target, ("update-ref", "-m", "hlith: land", "HEAD", new, parent))
    if up.returncode != 0:
        why = up.stderr.decode("utf-8", "replace").strip()[:200]
        # only an OBSERVED move is a CAS race; any other update-ref failure (held ref lock, broken ref store) is an integrity error
        # under its own name, never relabelled "head moved" (OCR lead on eb96f219, git_write.py:211-213)
        try:
            moved = head_commit(target) != parent
        except HostIntegrityError:
            moved = False
        if moved:
            raise HeadMovedError(f"gate: HEAD moved during landing ({why})")
        raise HostIntegrityError(f"gate: update-ref failed with HEAD unchanged ({why})")
    return new


def dirty_target_reason(target: Path, paths: list[str] | tuple[str, ...] = ()) -> str | None:
    """Return a non-None reason if ``target`` has staged/worktree changes or untracked collisions on ``paths``."""
    st = run_target_git(target, ("status", "--porcelain=v1", "-z", "--untracked-files=no"))
    if st.returncode != 0:
        return "target-status-unreadable"
    if st.stdout:
        return "target-dirty"
    cached = run_target_git(target, ("diff", "--cached", "--quiet"))
    if cached.returncode != 0:
        return "target-dirty-staged"
    if paths:
        # --ignored=matching: an ordinary gitignored local file at a path the patch CREATES would make `apply` fail after the journal began
        col = run_target_git(target, ("status", "--porcelain=v1", "-z", "--ignored=matching", "--", *paths))
        if col.returncode != 0 or col.stdout:
            return "target-dirty-touched-paths"
    return None


def _blob_at(target: Path, rev: str, rel: str) -> str:
    cp = run_target_git(target, ("ls-tree", "-z", rev, "--", rel))
    if cp.returncode != 0:
        raise HostIntegrityError(f"gate: cannot read {rel!r} at {rev[:12]} during recovery")
    rec = cp.stdout.split(b"\0")[0]
    return rec.split(b"\t", 1)[0].decode("ascii").split()[2] if b"\t" in rec else ""


def rollback_paths(target: Path, base_head: str, paths: list[str], images: dict[str, list[str]], *, restore_to: str | None = None) -> str:
    """Safely roll back only paths whose current worktree blob matches pre or post image.

    ``restore_to`` (default ``base_head``) is the commit whose content the touched paths get back. After a refused CAS (HEAD moved to
    another writer's commit) it is the LIVE HEAD: restoring from the stale base would leave that writer's committed content reverted in
    the index/worktree. Its blob is then also recognised as legitimate current content."""
    rev = restore_to or base_head
    for rel in paths:
        allowed = set(images.get(rel, []))
        if restore_to is not None:
            allowed.add(_blob_at(target, rev, rel))
        cur = worktree_blob_oid(target, rel)
        if cur not in allowed:
            raise HostIntegrityError(f"gate: refusing rollback of {rel!r} (unrecognized worktree content)")
    if paths:
        cp = run_target_git(target, ("reset", "-q", rev, "--", *paths))
        if cp.returncode != 0:
            why = cp.stderr.decode("utf-8", "replace").strip().replace("\n", " ")[:200]
            raise HostIntegrityError(f"gate: path-limited git reset failed during recovery ({why})")
    for rel in paths:
        present = _blob_at(target, rev, rel) if restore_to is not None else (images.get(rel) or ["", ""])[0]
        if present:
            if run_target_git(target, ("checkout", rev, "--", rel)).returncode != 0:
                raise HostIntegrityError(f"gate: git checkout failed during recovery of {rel!r}")
        else:
            full = Path(target) / rel
            if full.exists() or full.is_symlink():
                full.unlink()
    return f"recovered:{rev[:12]}"
