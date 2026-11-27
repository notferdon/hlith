# SPDX-License-Identifier: Apache-2.0
"""Host-owned sealed snapshots implementing ``contract.capabilities.SnapshotService``."""

from __future__ import annotations

import atexit
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from ..contract.capabilities import GitRead, SealedSnapshot, SnapshotService
from ..contract.identities import tree_oid
from .git_read import _HARDEN, HardenedGitRead, _check_symlink, scrubbed_git_env
from .integrity import HostIntegrityError


_RESERVED = {".git", ".hlith"}


def _has_reserved_or_escape(path: str) -> bool:
    parts = [c.lower() for c in path.split("/")]
    return any(c in _RESERVED for c in parts) or ".." in parts or path.startswith("/")


_HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


def _header_lines_outside_hunks(lines: list[str]) -> list[str]:
    """Return only diff header lines (outside @@ hunk bodies) so content lines cannot spoof or false-trigger headers."""
    out: list[str] = []
    old_rem = 0
    new_rem = 0
    for ln in lines:
        if old_rem > 0 or new_rem > 0:
            if ln.startswith("diff --git "):
                old_rem = new_rem = 0
            elif ln.startswith("\\"):
                continue
            elif ln.startswith("-"):
                old_rem = max(0, old_rem - 1)
                continue
            elif ln.startswith("+"):
                new_rem = max(0, new_rem - 1)
                continue
            else:
                old_rem = max(0, old_rem - 1)
                new_rem = max(0, new_rem - 1)
                continue
        m = _HUNK_RE.match(ln)
        if m:
            old_rem = int(m.group(1)) if m.group(1) is not None else 1
            new_rem = int(m.group(2)) if m.group(2) is not None else 1
            continue
        out.append(ln)
    return out


def _git_diff_candidate_pairs(header_rest: str) -> list[tuple[str, str]]:
    """Return every possible (a_path, b_path) split of 'a/<x> b/<y>' in case a path contains ' b/'."""
    if not header_rest.startswith("a/"):
        return []
    pairs: list[tuple[str, str]] = []
    idx = 2
    while True:
        pos = header_rest.find(" b/", idx)
        if pos < 0:
            break
        pairs.append((header_rest[2:pos], header_rest[pos + 3 :]))
        idx = pos + 1
    return pairs


def patch_violations(diff: str) -> list[str]:
    """Defence in depth: reject non-git-diff headers, reserved paths, gitlinks, and unsafe symlinks."""
    bad: list[str] = []
    all_lines = diff.split("\n")
    first_nonempty = next((ln for ln in all_lines if ln.strip()), "")
    if first_nonempty and not first_nonempty.startswith("diff --git "):
        bad.append("non-git-diff-header")
    for ln in _header_lines_outside_hunks(all_lines):
        if ln.startswith(("diff --git ", "--- ", "+++ ", "rename from ", "rename to ", "copy from ", "copy to ")) and '"' in ln:
            bad.append("c-quoted-path-header")
        if ln.startswith(("--- ", "+++ ")):
            p = ln[4:].strip()
            if p != "/dev/null":
                if p.startswith(("a/", "b/")):
                    p = p[2:]
                if _has_reserved_or_escape(p):
                    bad.append(f"reserved-or-escaping-path:{p}")
        elif ln.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            p = ln.split(" ", 2)[2]
            if _has_reserved_or_escape(p):
                bad.append(f"reserved-or-escaping-path:{p}")
    links: dict[str, str] = {}
    for sec in re.split(r"(?m)^diff --git ", diff)[1:]:
        lines = sec.split("\n")
        hdr_lines = _header_lines_outside_hunks(lines)
        cand_pairs = _git_diff_candidate_pairs(lines[0]) if lines else []
        plus_paths: list[str] = []
        for hln in hdr_lines:
            if hln.startswith("+++ "):
                hp = hln[4:].strip()
                if hp != "/dev/null":
                    plus_paths.append(hp[2:] if hp.startswith("b/") else hp)
            elif hln.startswith(("rename to ", "copy to ")):
                plus_paths.append(hln.split(" ", 2)[2])
        for a_p, b_p in cand_pairs:
            for p in (a_p, b_p):
                if _has_reserved_or_escape(p):
                    bad.append(f"reserved-or-escaping-path:{p}")
        if re.search(r"(?m)(mode|^index \S+) ?160000", "\n".join(hdr_lines)):
            bad.append("gitlink")
        if re.search(r"(?m)^GIT binary patch\b", "\n".join(hdr_lines)) and re.search(r"(?m)\b1[26]0000\b", "\n".join(hdr_lines)):
            bad.append("binary-patch-special-mode")
        hdr_text = "\n".join(hdr_lines)
        if re.search(r"(?m)^(?:new file mode|new mode) 120000", hdr_text) or re.search(r"(?m)^index \S+ 120000", hdr_text):
            tgt = [ln[1:] for ln in lines if ln.startswith("+") and not ln.startswith("+++")]
            fpath_candidates = plus_paths or [b_p for _, b_p in cand_pairs] or [""]
            if not tgt:
                bad.append(f"symlink-missing-target:{fpath_candidates[0]}")
                continue
            link = tgt[0]
            for fpath in fpath_candidates:
                norm = os.path.normpath(os.path.join(os.path.dirname(fpath), link))
                if any(c.lower() in _RESERVED for c in norm.split("/")):
                    bad.append(f"symlink-into-reserved:{fpath}->{link}")
                links[os.path.normpath(fpath)] = norm
                if link.startswith("/") or norm.startswith(".."):
                    bad.append(f"symlink-leaves-repo:{fpath}->{link}")
    for start in links:
        seen, cur = set(), start
        while cur in links:
            if cur in seen:
                bad.append(f"symlink-cycle:{start}")
                break
            seen.add(cur)
            cur = links[cur]
    return bad


def _check_snapshot_symlink(rel_posix: str, link: str) -> None:
    """Reject symlinks leaving the snapshot tree or targeting reserved directories."""
    _check_symlink(rel_posix, link)
    norm = posixpath.normpath(posixpath.join(posixpath.dirname(rel_posix), link))
    if any(c.lower() in _RESERVED for c in norm.split("/")):
        raise HostIntegrityError(f"unsafe symlink into reserved path {rel_posix!r} -> {link!r}")


def _retry_writable_remove(func, target: str) -> None:
    """Ensure parent directory and target allow unlink/rmdir, then retry cleanup."""
    parent = os.path.dirname(target)
    try:
        if parent and os.path.exists(parent):
            os.chmod(parent, os.stat(parent).st_mode | stat.S_IWUSR | stat.S_IXUSR)
    except OSError:
        pass
    try:
        if not os.path.islink(target) and os.path.exists(target):
            mode = stat.S_IRWXU if os.path.isdir(target) else (os.stat(target).st_mode | stat.S_IWUSR)
            os.chmod(target, mode)
    except OSError:
        pass
    func(target)


def _rmtree_force(path: Path) -> None:
    """Best-effort recursive removal that handles read-only trees cleanly."""
    if not path.exists() and not path.is_symlink():
        return
    if path.is_symlink():
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return
    try:
        if sys.version_info >= (3, 12):
            def _onexc(func, target: str, _exc: BaseException) -> None:
                _retry_writable_remove(func, target)

            shutil.rmtree(path, onexc=_onexc)
        else:
            def _onerror(func, target: str, _exc_info) -> None:
                _retry_writable_remove(func, target)

            shutil.rmtree(path, onerror=_onerror)
    except OSError:
        shutil.rmtree(path, ignore_errors=True)


_ATEXIT_LOCK = threading.Lock()
_ATEXIT_WORK_DIRS: set[Path] = set()


def _cleanup_atexit_work_dirs() -> None:
    with _ATEXIT_LOCK:
        dirs = list(_ATEXIT_WORK_DIRS)
        _ATEXIT_WORK_DIRS.clear()
    for work in dirs:
        _rmtree_force(work)


atexit.register(_cleanup_atexit_work_dirs)


def _copy_clean_tree(src: Path, dst: Path) -> None:
    if os.path.islink(src):
        raise HostIntegrityError(f"snapshot root must not be a symlink: {src}")
    dst.mkdir(parents=True, exist_ok=True)
    for root, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        rel_root = Path(root).relative_to(src)
        target_dir = dst / rel_root
        target_dir.mkdir(parents=True, exist_ok=True)
        for d in dirs:
            d_src = Path(root) / d
            if os.path.islink(d_src):
                link = os.readlink(d_src)
                _check_snapshot_symlink((rel_root / d).as_posix(), link)
                os.symlink(link, target_dir / d)
        for name in files:
            f_src = Path(root) / name
            f_dst = target_dir / name
            if os.path.islink(f_src):
                link = os.readlink(f_src)
                _check_snapshot_symlink((rel_root / name).as_posix(), link)
                os.symlink(link, f_dst)
            elif f_src.is_file():
                shutil.copy2(f_src, f_dst)
            else:
                raise HostIntegrityError(f"unsupported special file in snapshot: {f_src}")


def _run_scratch_git(repo: Path, ceiling: Path, args: tuple[str, ...], *, input_bytes: bytes | None = None) -> bytes:
    cmd = ["git", "--no-pager", *_HARDEN, "-C", str(repo), *args]
    try:
        cp = subprocess.run(
            cmd,
            input=input_bytes,
            capture_output=True,
            env=scrubbed_git_env(ceiling),
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HostIntegrityError(f"scratch git {args[0]} could not run: {getattr(exc, 'strerror', None) or exc}") from None
    if cp.returncode != 0:
        err = cp.stderr.decode("utf-8", "replace").strip()[:300]
        raise HostIntegrityError(f"scratch git {args[0]} failed: {err}")
    return cp.stdout


class LocalSnapshotService(SnapshotService):
    """Creates host-owned ``SealedSnapshot`` exports without mutating ``R_target``."""

    def __init__(self, git_read: GitRead | None = None, *, root: Path | None = None, cleanup_on_exit: bool = True) -> None:
        self._git_read = git_read or HardenedGitRead()
        self._root = Path(root) if root is not None else None
        self._cleanup_on_exit = bool(cleanup_on_exit)
        self._lock = threading.Lock()
        self._owned: dict[Path, Path] = {}

    def __enter__(self) -> LocalSnapshotService:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _mkdtemp(self, prefix: str) -> Path:
        if self._root is not None:
            self._root.mkdir(parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix=prefix, dir=self._root))

    def _track(self, tree_path: Path, work: Path) -> None:
        with self._lock:
            self._owned[tree_path] = work
        if self._cleanup_on_exit:
            with _ATEXIT_LOCK:
                _ATEXIT_WORK_DIRS.add(work)

    def owned_dirs(self) -> tuple[Path, ...]:
        """Return currently owned snapshot work directories awaiting release."""
        with self._lock:
            return tuple(self._owned.values())

    def release(self, snapshot: SealedSnapshot | Path) -> bool:
        """Remove the host temporary directory backing ``snapshot`` if owned by this service."""
        key = snapshot.path if isinstance(snapshot, SealedSnapshot) else Path(snapshot)
        with self._lock:
            work = self._owned.pop(key, None)
            if work is None:
                for snap_path, work_dir in self._owned.items():
                    if work_dir == key:
                        work = self._owned.pop(snap_path)
                        break
        if work is None:
            return False
        with _ATEXIT_LOCK:
            _ATEXIT_WORK_DIRS.discard(work)
        _rmtree_force(work)
        return True

    def close(self) -> None:
        """Release all remaining snapshot directories created by this service (idempotent)."""
        with self._lock:
            works = list(self._owned.values())
            self._owned.clear()
        if works:
            with _ATEXIT_LOCK:
                for work in works:
                    _ATEXIT_WORK_DIRS.discard(work)
            for work in works:
                _rmtree_force(work)

    def seal_base(self, repo: Path) -> SealedSnapshot:
        reason = self._git_read.repository_hostile_reason(repo)
        if reason is not None:
            raise HostIntegrityError(f"cannot seal hostile repository: {reason}")
        oid = self._git_read.head_tree(repo)
        work = self._mkdtemp(f"hlith-base-{oid[:12]}-")
        dest = work / "tree"
        try:
            self._git_read.export_tree(repo, oid, dest)
        except BaseException:
            _rmtree_force(work)
            raise
        self._track(dest, work)
        return SealedSnapshot(tree_oid=oid, path=dest)

    def reconstruct_post(self, base: SealedSnapshot, patch: bytes) -> SealedSnapshot:
        if not base.path.is_dir():
            raise HostIntegrityError(f"base snapshot missing: {base.path}")
        if patch.strip():
            pv = patch_violations(patch.decode("utf-8", "surrogateescape"))
            if pv:
                raise HostIntegrityError(f"patch-policy-violation: {'; '.join(pv)}")
        work = self._mkdtemp("hlith-post-")
        scratch = work / "repo"
        post_tree = work / "tree"
        try:
            _copy_clean_tree(base.path, scratch)
            _run_scratch_git(scratch, work, ("init", "-q"))
            # The scratch tree must be EXACTLY base + patch: no end-of-line/ident/encoding/filter conversion from the tree's own .gitattributes (text=auto would rewrite CRLF files the
            # patch never touched, the verified post tree would then differ from what the gate lands, and every landing in such a repository would be refused). info/attributes has the
            # highest precedence of all attribute sources.
            (scratch / ".git" / "info").mkdir(exist_ok=True)
            (scratch / ".git" / "info" / "attributes").write_text("* -text -eol -ident -filter -working-tree-encoding\n", encoding="utf-8")
            # The sealed base is already the complete set of tracked paths. Ignore
            # rules from that tree (or the host's global excludes) must not filter
            # it while rebuilding the scratch index.
            _run_scratch_git(scratch, work, ("add", "-f", "-A"))
            _run_scratch_git(
                scratch,
                work,
                ("-c", "user.name=hlith", "-c", "user.email=hlith@invalid.local", "commit", "-q", "--no-verify", "--allow-empty", "-m", "base"),
            )
            if patch.strip():
                _run_scratch_git(scratch, work, ("apply", "--check"), input_bytes=patch)
                _run_scratch_git(scratch, work, ("apply", "--index"), input_bytes=patch)
            post_oid = tree_oid(_run_scratch_git(scratch, work, ("write-tree",)).decode("ascii").strip())
            self._git_read.export_tree(scratch, post_oid, post_tree)
            _rmtree_force(scratch)
        except BaseException:
            _rmtree_force(work)
            raise
        self._track(post_tree, work)
        return SealedSnapshot(tree_oid=post_oid, path=post_tree)
