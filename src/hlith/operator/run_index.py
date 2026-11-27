# SPDX-License-Identifier: Apache-2.0
"""Read-only, bounded history directory discovery and ranking shared by OperatorApi and TUI launch."""

from __future__ import annotations

import heapq
import json
import math
import os
import re
import stat
import time
from pathlib import Path

from .state import HostIntegrityError, LocalState, state_root as engine_state_root

MAX_HISTORY_REPOSITORIES = 1024
MAX_HISTORY_SCAN_CANDIDATES = 5000
SCAN_WINDOW = 64
MAX_HISTORY_START_SKEW = 24 * 60 * 60
MAX_RUN_META_BYTES = 64 * 1024
RUN_DIR_RE = re.compile(r"(?:launch|run)-[0-9a-f]{12}\Z")
REPO_DIR_RE = re.compile(r"repo-[0-9a-f]{24}\Z")


def is_real_directory(path: Path) -> bool:
    """Check the final path component with lstat so state roots cannot redirect through a symlink."""
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except OSError:
        return False


def read_run_file(path: Path, limit: int) -> bytes:
    """Read a small regular metadata file without following links or blocking on special files."""
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ValueError("not a bounded regular file")
        raw = bytearray()
        while len(raw) <= limit:
            chunk = os.read(fd, min(8192, limit + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) > limit:
            raise ValueError("file changed beyond its read limit")
        return bytes(raw)
    finally:
        os.close(fd)


def finite_started(value) -> float | None:
    """Return a finite run timestamp, excluding booleans and hostile/non-finite JSON numbers."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    return number if math.isfinite(number) else None


def credible_started(value, *, now: float | None = None, max_skew: float = MAX_HISTORY_START_SKEW) -> float | None:
    """Clamp small clock skew; treat implausibly future timestamps as unrecorded."""
    now = time.time() if now is None else now
    started = finite_started(value)
    if started is None or started > now + max_skew:
        return None
    return min(started, now)


def history_order_key(meta: dict, modified: float, *, now: float, tie: str = "", max_skew: float = MAX_HISTORY_START_SKEW) -> tuple:
    """Shared history ranking: credible engine start first; otherwise bounded directory mtime."""
    started = credible_started(meta.get("started"), now=now, max_skew=max_skew)
    modified_f = finite_started(modified)
    modified_f = min(modified_f, now) if modified_f is not None else 0.0
    if started is not None:
        return (1, started, modified_f, str(meta.get("run_id") or ""), tie)
    return (0, modified_f, modified_f, str(meta.get("run_id") or ""), tie)


def bounded_child_dirs(base: Path, name_pattern, limit: int, *, rank_by_started: bool = False) -> list[Path]:
    """Rank real child directories before applying the result cap; never follow a child symlink."""
    if limit <= 0:
        return []
    try:
        if not stat.S_ISDIR(base.lstat().st_mode):
            return []
        found = []
        with os.scandir(base) as entries:
            for entry in entries:
                if not name_pattern.fullmatch(entry.name):
                    continue
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    path = Path(entry.path)
                    started = None
                    if rank_by_started:
                        try:
                            meta = json.loads(read_run_file(path / "meta.json", MAX_RUN_META_BYTES).decode("utf-8"))
                        except (OSError, ValueError, UnicodeError, TypeError):
                            continue
                        if not isinstance(meta, dict) or meta.get("run_id") != path.name:
                            continue
                        started = finite_started(meta.get("started"))
                    rank = started if started is not None else info.st_mtime
                    found.append((rank, info.st_mtime, path.name, path))
        return [row[3] for row in heapq.nlargest(limit, found, key=lambda row: row[:3])]
    except OSError:
        return []


def current_runs_dir(st_root: Path, current_repo) -> Path | None:
    if current_repo is None:
        return None
    try:
        return LocalState(st_root).existing_runs_dir(Path(current_repo))
    except (OSError, ValueError, HostIntegrityError):
        return None


def history_bases(
    st_root: Path,
    repo=None,
    current_repo=None,
    *,
    max_repositories: int = MAX_HISTORY_REPOSITORIES,
    extra_roots: tuple[Path, ...] = (),
) -> list[Path]:
    bases = [st_root / "runs"]  # pre-freeze UI layout: read-only history
    host_root = engine_state_root(st_root)
    existing_roots = [
        root for root in dict.fromkeys((*extra_roots, host_root, st_root / "host"))
        if is_real_directory(root) and is_real_directory(root / "repositories")
    ]
    if not existing_roots:
        return bases
    current = current_runs_dir(st_root, repo or current_repo)
    identity = current.parent.name if current is not None else None
    if identity is None and (repo or current_repo) is not None:
        try:
            identity = LocalState(st_root).stable_repo_identity(Path(repo or current_repo))
        except HostIntegrityError:
            pass
    # Previous UI versions wrote launches under the preferences directory even
    # when the CLI had an explicit engine store. Keep that history readable.
    for root in existing_roots:
        repositories = root / "repositories"
        if identity:
            current = repositories / identity / "runs"
            if is_real_directory(current):
                bases.append(current)
        if repo is None:
            children = bounded_child_dirs(repositories, REPO_DIR_RE, max_repositories + 1)
            others = [r / "runs" for r in children if r / "runs" not in bases]
            bases.extend(others[:max_repositories])
    return bases


def ranked_run_candidates(
    bases: list[Path],
    *,
    repo=None,
    max_candidates: int = MAX_HISTORY_SCAN_CANDIDATES,
    scan_window: int = SCAN_WINDOW,
):
    """Read at most the bounded candidate budget across all roots, while counting every matching run directory."""
    now = time.time()
    repo_key = str(Path(repo).resolve()) if repo is not None else None
    pending = [base for base in bases if is_real_directory(base)]

    def open_more(active: list) -> list:
        while pending and len(active) < scan_window:
            try:
                scan = os.scandir(pending.pop(0))
            except OSError:
                continue
            active.append((scan, iter(scan)))
        return active

    found = []
    seen = set()
    total = 0
    scanned = 0
    active = open_more([])
    while active:
        next_active = []
        for scan, entries in active:
            try:
                entry = next(entries)
            except StopIteration:
                close = getattr(scan, "close", None)
                if close is not None:
                    close()
                else:
                    scan.__exit__(None, None, None)
                continue
            except OSError:
                close = getattr(scan, "close", None)
                if close is not None:
                    close()
                else:
                    scan.__exit__(None, None, None)
                continue
            next_active.append((scan, entries))
            if not RUN_DIR_RE.fullmatch(entry.name):
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISDIR(info.st_mode):
                continue
            path = Path(entry.path)
            key_path = os.path.abspath(path)
            if key_path in seen:
                continue
            seen.add(key_path)
            total += 1
            if scanned >= max_candidates:
                continue
            scanned += 1
            try:
                meta = json.loads(read_run_file(path / "meta.json", MAX_RUN_META_BYTES).decode("utf-8"))
            except (OSError, ValueError, UnicodeError, TypeError):
                continue
            if not isinstance(meta, dict) or meta.get("run_id") != path.name:
                continue
            if repo_key is not None and meta.get("source_repo") != repo_key:
                continue
            found.append((history_order_key(meta, info.st_mtime, now=now, tie=key_path), path))
        active = open_more(next_active)

    found.sort(key=lambda row: row[0], reverse=True)
    return found, total, min(total, max_candidates), total > max_candidates, now


def omitted_history_repositories(
    st_root: Path,
    repo=None,
    current_repo=None,
    *,
    max_repositories: int = MAX_HISTORY_REPOSITORIES,
) -> int:
    """How many repository folders the history scan does NOT read."""
    if repo is not None:
        return 0
    repositories = engine_state_root(st_root) / "repositories"
    if not is_real_directory(repositories):
        return 0
    try:
        with os.scandir(repositories) as entries:
            n = sum(1 for e in entries if REPO_DIR_RE.fullmatch(e.name) and e.is_dir(follow_symlinks=False))
    except OSError:
        return 0
    cur = current_runs_dir(st_root, current_repo)
    if cur is not None and (repositories / cur.parent.name).is_dir():
        n -= 1
    return max(0, n - max_repositories)
