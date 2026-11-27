# SPDX-License-Identifier: Apache-2.0
"""Read-only git queries for the operator TUI. This module owns only PROCESS MANAGEMENT (process groups, cancel-on-quit, timeouts); the argv, the environment and the
repository vet are the single choke point in ``hostio.git_read`` (closed-world config allowlist, fail-closed, scrubbed env, explicit --git-dir/--work-tree,
--no-replace-objects). A repository the vet cannot prove safe is NOT inspected with any command: `refusal(repo)` names why and the screen says so. A config or HEAD
change DURING a command discards its output. Never writes to the repository, its index or its worktree."""

from __future__ import annotations

import atexit
import os
import re
import select
import signal
import shutil
import subprocess
import tempfile
import threading
import time
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..hostio import git_read as _ro  # read-only hardening policy lives in hostio (never the gate)
from ..hostio.git_read import (
    EMPTY_TREE,
    GitFeatureCheck,
    GitFeatureProbeResult,
    GitReadError,
    GitReadErrorKind,
    probe_git_features,
    require_supported_git,
)

TIMEOUT = 30
ALLOWED_ENV = _ro.ALLOWED_EXTRA_ENV  # the temp-index trick, nothing else
# overrides the gate's list does not (yet) carry: signature display runs a gpg program from the repository's own config (review T1); every program-naming key we know of is emptied on the command line
HARDEN = [*_ro._HARDEN, "-c", "core.quotepath=false", "-c", "log.showSignature=false", "-c", "gpg.program=", "-c", "gpg.openpgp.program=", "-c", "gpg.ssh.program=",
          "-c", "gpg.x509.program=",
          # a submodule has its OWN gitdir with its own config and info/attributes: the outer status/diff must never recurse into it (review S1)
          "-c", "diff.ignoreSubmodules=all", "-c", "status.submoduleSummary=false", "-c", "submodule.recurse=false"]
_NO_RECURSE = {"status", "diff", "diff-index", "diff-files", "diff-tree"}
_pairs = [(HARDEN[i], HARDEN[i + 1]) for i in range(0, len(HARDEN), 2)]
HARDEN_CLONE = [x for pair in _pairs if pair[1] != "protocol.allow=never" for x in pair]  # a local clone needs the file protocol; every other override stays
_CHILD_LOCK = threading.Lock()
_CHILDREN: weakref.WeakSet[subprocess.Popen] = weakref.WeakSet()
_CHILDREN_CANCELLED = False


def begin_session() -> None:
    """Allow child processes for a newly opened interactive TUI session."""
    global _CHILDREN_CANCELLED
    _ro.begin_session()
    with _CHILD_LOCK:
        _CHILDREN_CANCELLED = False


def _popen(args, **kwargs) -> subprocess.Popen:
    """Start a Git process in its own group so interactive shutdown can reap the whole group."""
    global _CHILDREN_CANCELLED
    with _CHILD_LOCK:
        if _CHILDREN_CANCELLED:
            raise OSError("TUI is shutting down")
        proc = subprocess.Popen(args, start_new_session=True, **kwargs)
        _CHILDREN.add(proc)
        return proc


def _run(args, *, capture_output=False, env=None, timeout=None, cwd=None, input=None):
    """Small subprocess.run equivalent whose active Git child can be stopped on UI quit."""
    proc = _popen(
        args,
        stdin=subprocess.PIPE if input is not None else None,
        stdout=subprocess.PIPE if capture_output or input is not None else None,
        stderr=subprocess.PIPE if capture_output else None,
        env=env,
        cwd=cwd,
    )
    try:
        stdout, stderr = proc.communicate(input=input, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = proc.communicate()
        raise subprocess.TimeoutExpired(args, timeout, output=stdout or exc.output, stderr=stderr or exc.stderr) from exc
    finally:
        with _CHILD_LOCK:
            _CHILDREN.discard(proc)
    return subprocess.CompletedProcess(args, proc.returncode, stdout, stderr)


def cancel_active_children() -> None:
    """Stop all active Git process groups and refuse new children for this TUI session."""
    global _CHILDREN_CANCELLED
    _ro.cancel_active_children()
    with _CHILD_LOCK:
        _CHILDREN_CANCELLED = True
        children = tuple(_CHILDREN)
    for proc in children:
        if proc.poll() is not None:
            continue
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
    deadline = time.monotonic() + 0.2
    for proc in children:
        remaining = deadline - time.monotonic()
        if remaining > 0:
            try:
                proc.wait(timeout=remaining)
                continue
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass


def _home() -> str:
    return _ro.private_home()


def scrubbed_env(extra=None) -> dict:
    """The only environment a git child of the screen gets: hostio.git_read's positive allowlist. `extra` may carry ALLOWED_ENV names only, pointing where the temp-index trick needs."""
    return _ro.scrubbed_git_env(None, extra)


def _cmd(repo, cwd, args, flags=None) -> list[str]:
    if cwd is not None:
        raise ValueError("gitq: a repository-bound command never takes a caller cwd (the choke point pins --git-dir and --work-tree)")
    cmd = _ro.readonly_argv(repo, [], pre=(f"--attr-source={EMPTY_TREE}",), flags=HARDEN if flags is None else flags)  # explicit --git-dir AND --work-tree
    args = list(args)
    sub = next((i for i, a in enumerate(args) if not a.startswith("-")), None)  # the subcommand (global options like --literal-pathspecs may precede it)
    if sub is not None and args[sub] in ("log", "show"):
        args.insert(sub + 1, "--no-show-signature")
    elif sub is not None and args[sub] in _NO_RECURSE:
        args.insert(sub + 1, "--ignore-submodules=all")
    return cmd + args


def refusal(repo) -> str | None:
    """Why this repository is not inspected, or None. None ONLY when hostio.git_read.vet_repository proves the repository safe (closed-world config allowlist, plain .git, no
    symlinked refs/objects, owned by this user, ...); any error while checking is a refusal. Re-evaluated on EVERY call: a setting added after an earlier answer is seen by the next command."""
    why = _ro.vet_repository(Path(repo))
    if why is None:
        return None
    if why.startswith("target-git-dir-"):
        return (f"its .git is not a plain directory ({why}): a linked worktree, submodule or symlink points at some other repository, so the screen would show that one as this folder. "
                f"Clone this repository and open the clone")
    short = next((why.split(marker, 1)[1] for marker in ("config-key-not-allowed:", "config-value-not-allowed:") if marker in why), why)  # the KEY first: a narrow screen clips the tail
    return (f"this repository's own settings can run programs on this machine or are not on Hlith's safe list ({short}): Hlith does not inspect or check it from here. "
            f"Use a clean clone without those settings (the gate refuses to land into it for the same reason)")


def _checked_env(repo, env) -> dict:
    """scrubbed_env + the repo-aware rule: a caller-supplied alternate object store may only be THIS repository's own (the temp-index trick), never another repository's."""
    alt = (env or {}).get("GIT_ALTERNATE_OBJECT_DIRECTORIES")
    if alt is not None and os.path.realpath(alt) != os.path.realpath(Path(repo).resolve() / ".git" / "objects"):
        raise ValueError(f"GIT_ALTERNATE_OBJECT_DIRECTORIES names another object store: {alt!r}")
    return scrubbed_env(env)


@dataclass(frozen=True)
class GitResult:
    """Typed result from a completed hardened read-only Git command."""

    stdout: bytes
    stderr: bytes
    returncode: int


@dataclass
class GitStream:
    """Handle for a streaming hardened Git read that preserves stderr and config/HEAD fingerprinting."""

    proc: subprocess.Popen
    repo: Path
    cmd: tuple[str, ...]
    before_fp: tuple
    _finished: bool = False


def run(
    repo,
    *args,
    env=None,
    cwd=None,
    allow_returncodes: tuple[int, ...] = (0,),
    require_empty_stderr_for_nonzero: bool = True,
) -> GitResult:
    """Execute a hardened read-only Git query and return typed ``GitResult``, or raise ``GitReadError``.

    Empty successful stdout (exit 0) is ALWAYS distinguishable from refusal, unsupported feature,
    unexpected nonzero exit, timeout, spawn failure, cancellation, or mid-read config/HEAD change.
    """
    why = refusal(repo)  # before ANY command, plumbing included (review T1: `log` ran a gpg program)
    if why:
        raise GitReadError(GitReadErrorKind.REPOSITORY_REFUSED, why)
    real = Path(repo).resolve()
    before = _ro._fingerprint(real)
    cmd = _cmd(repo, cwd, args)
    try:
        checked = _checked_env(repo, env)
    except ValueError as ex:
        raise GitReadError(GitReadErrorKind.SPAWN_FAILED, str(ex)) from ex
    try:
        p = _run(cmd, capture_output=True, env=checked, timeout=TIMEOUT)
    except subprocess.TimeoutExpired as ex:
        raise GitReadError(
            GitReadErrorKind.TIMEOUT,
            f"git {args[0] if args else ''} timed out after {TIMEOUT}s",
        ) from ex
    except OSError as ex:
        kind = GitReadErrorKind.CANCELLED if "shutting down" in str(ex).lower() else GitReadErrorKind.SPAWN_FAILED
        raise GitReadError(kind, f"cannot run git ({ex.strerror or ex})") from ex
    except (subprocess.SubprocessError, ValueError) as ex:
        raise GitReadError(GitReadErrorKind.SPAWN_FAILED, str(ex)) from ex
    if _ro._fingerprint(real) != before:
        raise GitReadError(
            GitReadErrorKind.CONCURRENT_MUTATION,
            "the repository's config or HEAD changed while it was being read: result discarded",
        )
    if p.returncode not in allow_returncodes or (
        p.returncode != 0 and require_empty_stderr_for_nonzero and p.stderr.strip()
    ):
        raise _ro._classify_git_failure(cmd, p.returncode, p.stderr)
    return GitResult(stdout=p.stdout, stderr=p.stderr, returncode=p.returncode)


def read(repo, *args, env=None, cwd=None, allow_returncodes: tuple[int, ...] = (0,)) -> bytes:
    """Strict hardened Git stdout bytes; raises ``GitReadError`` on any failure."""
    return run(repo, *args, env=env, cwd=cwd, allow_returncodes=allow_returncodes).stdout


def read_text(repo, *args, env=None, cwd=None, allow_returncodes: tuple[int, ...] = (0,)) -> str:
    """Strict hardened Git stdout text (stripped); raises ``GitReadError`` on any failure."""
    return read(repo, *args, env=env, cwd=cwd, allow_returncodes=allow_returncodes).decode("utf-8", "replace").strip()


def optional_text(repo, *args, env=None, cwd=None) -> str | None:
    """Hardened query whose documented 'absent' answer is exit 1 with empty stderr (e.g. ``rev-parse --verify -q``,
    ``symbolic-ref -q``, ``merge-base``).

    Returns ``None`` ONLY on exit 1 with empty stderr. Any other nonzero exit (such as exit 129 for an unsupported
    option like ``--attr-source`` or exit 128 fatal error), non-empty stderr on exit 1, timeout, spawn error,
    refusal, or mid-read mutation raises ``GitReadError``.
    """
    res = run(repo, *args, env=env, cwd=cwd, allow_returncodes=(0, 1), require_empty_stderr_for_nonzero=True)
    if res.returncode == 1:
        return None
    return res.stdout.decode("utf-8", "replace").strip()


def git(repo, *args, env=None, cwd=None, check=False) -> bytes:
    """stdout bytes of a hardened `git -C repo ...`; raises ``GitReadError`` when ``check=True``.
    Legacy ``check=False`` returns b'' on refusal/error for existing low-level callers; safety-sensitive
    consumers must use ``run`` / ``read`` / ``read_text`` / ``optional_text`` / ``check=True``."""
    try:
        return run(repo, *args, env=env, cwd=cwd).stdout
    except GitReadError:
        if check:
            raise
        return b""


def open_stream(repo, args, env=None) -> GitStream:
    """Start a streaming hardened Git child with both stdout and stderr piped plus pre-read fingerprinting."""
    why = refusal(repo)
    if why:
        raise GitReadError(GitReadErrorKind.REPOSITORY_REFUSED, why)
    real = Path(repo).resolve()
    before = _ro._fingerprint(real)
    cmd = _cmd(repo, None, args)
    try:
        checked = _checked_env(repo, env)
    except ValueError as ex:
        raise GitReadError(GitReadErrorKind.SPAWN_FAILED, str(ex)) from ex
    try:
        proc = _popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=checked)
    except OSError as ex:
        kind = GitReadErrorKind.CANCELLED if "shutting down" in str(ex).lower() else GitReadErrorKind.SPAWN_FAILED
        raise GitReadError(kind, f"cannot run git ({ex.strerror or ex})") from ex
    return GitStream(proc=proc, repo=real, cmd=tuple(cmd), before_fp=before)


def drain_stream(
    stream: GitStream,
    *,
    on_chunk: Callable[[bytes], bool],
    timeout: float = TIMEOUT * 4,
    stderr_cap: int = 8192,
) -> tuple[bool, bool, bytes]:
    """Drain stdout and bounded stderr without pipe deadlock. Returns ``(killed_for_limit, timed_out, stderr_bytes)``."""
    proc = stream.proc
    assert proc.stdout is not None and proc.stderr is not None
    out_fd = proc.stdout.fileno()
    err_fd = proc.stderr.fileno()
    open_fds = [out_fd, err_fd]
    err_buf = bytearray()
    killed_for_limit = False
    timed_out = False
    deadline = time.monotonic() + timeout
    while open_fds:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            break
        ready, _, _ = select.select(open_fds, [], [], min(remaining, 0.5))
        if not ready:
            continue
        if out_fd in ready:
            chunk = os.read(out_fd, 65536)
            if not chunk:
                open_fds.remove(out_fd)
            elif not on_chunk(chunk):
                killed_for_limit = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                break
        if err_fd in ready:
            echunk = os.read(err_fd, 4096)
            if not echunk:
                open_fds.remove(err_fd)
            elif len(err_buf) < stderr_cap:
                err_buf.extend(echunk[: stderr_cap - len(err_buf)])
    return killed_for_limit, timed_out, bytes(err_buf)


def finish_stream(
    stream: GitStream,
    *,
    stderr_bytes: bytes = b"",
    killed_for_limit: bool = False,
    timed_out: bool = False,
    allow_returncodes: tuple[int, ...] = (0,),
    timeout: float = TIMEOUT,
) -> None:
    """Reap a streaming hardened Git child, validate fingerprint and return code, or raise ``GitReadError``."""
    proc = stream.proc
    extra_err = b""
    try:
        if proc.poll() is None:
            try:
                proc.wait(timeout=max(0.5, min(timeout, 5.0)))
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=2.0)
        if not stderr_bytes and proc.stderr is not None and not proc.stderr.closed:
            try:
                extra_err = proc.stderr.read(4096)
            except OSError:
                extra_err = b""
    finally:
        for pipe in (proc.stdout, proc.stderr):
            if pipe is not None and not pipe.closed:
                try:
                    pipe.close()
                except OSError:
                    pass
        with _CHILD_LOCK:
            _CHILDREN.discard(proc)
        stream._finished = True
    combined_err = stderr_bytes or extra_err
    if timed_out:
        raise GitReadError(GitReadErrorKind.TIMEOUT, f"git timed out after {timeout:.0f}s")
    if _ro._fingerprint(stream.repo) != stream.before_fp:
        raise GitReadError(
            GitReadErrorKind.CONCURRENT_MUTATION,
            "the repository's config or HEAD changed while it was being read: result discarded",
        )
    if not killed_for_limit and proc.returncode not in allow_returncodes:
        raise _ro._classify_git_failure(stream.cmd, int(proc.returncode or 1), combined_err)


def popen(repo, args, env=None) -> subprocess.Popen:
    """A streaming hardened git (stdout piped) for bounded diff reads. OSError (with the reason as strerror) when the repository is refused."""
    why = refusal(repo)
    if why:
        raise OSError(1, why)
    return _popen(_cmd(repo, None, args), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_checked_env(repo, env))


def text(repo, *args, **kw) -> str:
    return git(repo, *args, **kw).decode("utf-8", "replace").strip()


def merge_conflict_paths(repo) -> list[str]:
    """Paths with unresolved merge conflicts in ``repo`` (porcelain v1 ``U`` or ``AA``/``DD``), or [].

    Raises ``GitReadError`` if Git cannot be executed safely (never silently returns ``[]`` on failure).
    """
    status = read(repo, "status", "--porcelain=v1", "-z", "--untracked-files=no")
    if not status:
        return []
    fields = status.split(b"\0")
    conflicted: list[str] = []
    i = 0
    while i < len(fields) and fields[i]:
        entry = fields[i]
        i += 1
        code = entry[:2].decode("ascii", "replace")
        path = os.fsdecode(entry[3:])
        if "R" in code or "C" in code:
            i += 1
        if "U" in code or code in {"AA", "DD"}:
            conflicted.append(path)
    return conflicted


def merge_conflict_reason(repo) -> str | None:
    """Plain refusal reason when ``repo`` has unresolved merge conflicts, else None. Raises ``GitReadError`` on Git failure."""
    conflicted = merge_conflict_paths(repo)
    if not conflicted:
        return None
    tail = "…" if len(conflicted) > 1 else ""
    return (
        f"a merge is in progress with unresolved conflicts in {len(conflicted)} file(s) "
        f"({conflicted[0]}{tail}): resolve or abort the merge before checking. Nothing was checked."
    )


def toplevel(path) -> tuple[Path | None, str]:
    """(repo root, '') for a path inside a work tree; (None, reason) otherwise, naming git's own complaint
    (e.g. 'not a git repository', 'detected dubious ownership')."""
    p = Path(path)
    if not p.exists():
        return None, f"{p} does not exist"
    # Discovery WITHOUT starting git: Git must not run inside a directory before the vet has passed (and a repository's own core.worktree must never name "the repository you
    # are in"). The root is the nearest ancestor that has a `.git` entry; whether it is a plain, safe repository is the vet's (and the shape check's) job.
    here = p.resolve()
    root = _ro.find_work_tree_root(here)  # requires a plausible .git (a stub .git in a parent such as a home directory is not a repository, exactly as for git)
    if root is None:
        return None, "not a git repository"
    shape = _ro._target_git_dir_violation(root)
    if shape:
        return None, f"{root}: .git is not a plain directory ({shape}); the screen will not follow it to another repository"
    why = _ro.vet_repository(root)
    # identity-class refusals (another git dir, symlinked refs/objects, alternates, foreign owner, a core.worktree that names another tree) mean "this is not the repository you
    # are in": no repository. Config-class refusals keep their own blocked screen via refusal().
    if why and (why.startswith(("target-git-", "target-objects", "target-not-owned", "target-grafts")) or "core.worktree" in why or "core.bare" in why):
        return None, f"{root}: {why}; the screen will not follow it to another repository"
    return root, ""


def numstat(patch: bytes) -> list[tuple[str, int | None, int | None]]:
    """(path, added, deleted) per file of a diff text, from `git apply --numstat -z` (no repository needed). Binary: (path, None, None)."""
    if not patch or not patch.strip():
        return []
    argv = ["git", "--no-pager", "apply", "--numstat", "-z", "-"]
    try:
        r = _run(argv, input=patch, capture_output=True, timeout=TIMEOUT, env=scrubbed_env(), cwd=_home())
    except subprocess.TimeoutExpired as exc:
        raise GitReadError(GitReadErrorKind.TIMEOUT, f"git apply --numstat timed out after {TIMEOUT}s") from exc
    except OSError as exc:
        kind = GitReadErrorKind.CANCELLED if "shutting down" in str(exc).lower() else GitReadErrorKind.SPAWN_FAILED
        raise GitReadError(kind, f"cannot run git ({exc.strerror or exc})") from exc
    except subprocess.SubprocessError as exc:
        raise GitReadError(GitReadErrorKind.SPAWN_FAILED, str(exc)) from exc
    if r.returncode != 0:
        err = _ro._classify_git_failure(argv, r.returncode, r.stderr)
        if err.kind is GitReadErrorKind.UNSUPPORTED_FEATURE:
            raise err
        return []
    out = []
    for rec in r.stdout.decode("utf-8", "replace").split("\0"):
        parts = rec.split("\t", 2)
        if len(parts) == 3:
            a, d, path = parts
            out.append((path, None if a == "-" else int(a), None if d == "-" else int(d)))
    return out
