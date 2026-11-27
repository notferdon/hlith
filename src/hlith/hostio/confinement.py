# SPDX-License-Identifier: Apache-2.0
"""Run a command under kernel confinement (user+mount ns, ro bind, Landlock)."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

_LAUNCHER = str(Path(__file__).with_name("confine_exec.py"))
_SYSTEM_RO = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/localtime", "/etc/alternatives", "/proc", "/dev/null", "/dev/zero", "/dev/urandom"]
EXIT_BOUNDARY = 4


class GrantError(RuntimeError):
    """A granted tree holds a socket / FIFO / device node, or is too big to vet: the run is refused (finding 24)."""


@dataclass(frozen=True)
class ConfinementBoundaryInfo:
    """Typed host confinement failure authored by ``confine_exec.py`` before ``execvp`` (unreachable by target code)."""

    code: str
    stage: str
    detail: str
    errno_num: int | None = None


class ConfinementBoundaryError(RuntimeError):
    """Typed host confinement boundary failure (maps to exit 4 BOUNDARY, never NOT-DERIVED exit 11 or INTERNAL exit 3)."""

    def __init__(self, info: ConfinementBoundaryInfo, message: str | None = None) -> None:
        self.info = info
        self.reason = message or f"{info.code}: {info.detail}"
        super().__init__(self.reason)


class ConfinedProcess(subprocess.CompletedProcess):
    """``subprocess.CompletedProcess`` carrying optional launcher-authored ``boundary_failure`` metadata."""

    def __init__(
        self,
        args,
        returncode: int,
        stdout=None,
        stderr=None,
        *,
        boundary_failure: ConfinementBoundaryInfo | None = None,
    ) -> None:
        super().__init__(args, returncode, stdout=stdout, stderr=stderr)
        self.boundary_failure = boundary_failure


def _read_boundary_failure(path: str, returncode: int) -> ConfinementBoundaryInfo | None:
    """Read a launcher-authored boundary status record if present and non-empty on exit 4."""
    if returncode != EXIT_BOUNDARY:
        return None
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > 4096:
            return None
        with open(path, "rb") as fh:
            raw = fh.read(4096)
        doc = json.loads(raw.decode("utf-8", "replace"))
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(doc, dict):
        return None
    code = doc.get("code")
    stage = doc.get("stage")
    detail = doc.get("detail")
    err_num = doc.get("errno")
    if not isinstance(code, str) or not code or not isinstance(stage, str) or not isinstance(detail, str):
        return None
    return ConfinementBoundaryInfo(
        code=code[:80],
        stage=stage[:80],
        detail=detail[:300],
        errno_num=err_num if type(err_num) is int else None,
    )


def raise_if_confinement_boundary(cp: subprocess.CompletedProcess) -> None:
    """Raise ``ConfinementBoundaryError`` iff the launcher recorded a host-side confinement failure before ``execvp``.

    Never inspects target stdout/stderr, so target code exiting 4 or printing fake Landlock errors is never misclassified.
    """
    bf = getattr(cp, "boundary_failure", None)
    if isinstance(bf, ConfinementBoundaryInfo):
        raise ConfinementBoundaryError(bf)


_SYSTEM_ROOTS = ("/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev")
_MAX_GRANT_ENTRIES = 2_000_000
_PREFIX_TTL = 600.0
_prefix_ok: dict[str, float] = {}  # host-controlled interpreter prefixes: vetted once per TTL (60k files ~ 1.7 s)


def _special(mode: int) -> bool:
    return stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode)


def _vet_tree(root: str, budget: list[int]) -> None:
    top = os.lstat(root)
    if not stat.S_ISDIR(top.st_mode):
        if _special(top.st_mode):
            raise GrantError(f"special file in a granted path: {root}")
        return
    for dp, dns, fns in os.walk(root, followlinks=False):
        for name in (*dns, *fns):
            budget[0] -= 1
            if budget[0] < 0:
                raise GrantError(f"granted paths hold more than {_MAX_GRANT_ENTRIES} entries; refusing to confine")
            p = os.path.join(dp, name)
            if _special(os.lstat(p).st_mode):
                raise GrantError(f"special file in a granted path: {p}")


def refuse_rw_over_ro_bind(spec: dict) -> None:
    """rw and ro_bind trees must be disjoint, in either direction, refused by name; mounts are never re-ordered around it.

    rw equal to or above an ro_bind path would make it writable (the launcher binds rw after ro/ro_bind, Landlock rules are additive).
    rw inside an ro_bind tree was measured contained (only the rw child became writable), but one disjointness invariant is easier to
    audit and keep true than a narrower-child exception, and no production caller overlaps (design policy, review-symmetric)."""
    for b in spec.get("ro_bind", []):
        for r in spec.get("rw", []):
            if b == r or b.startswith(r.rstrip("/") + "/") or r.startswith(b.rstrip("/") + "/"):
                raise GrantError(f"writable grant {r} overlaps read-only-bound path {b} (ro_bind): refusing to confine; "
                                 "keep rw grants disjoint from ro_bind paths")


LIVE_STATE_ROOTS: set[str] = set()  # filled by hostio.state.LocalHostState: every host state root (keys) this process constructed


def refuse_grant_over_host_state(spec: dict) -> None:
    """No grant (ro / rw / ro_bind) may equal, contain or sit inside the host state root (design plan).

    That root holds verifier-issue.key, gate-journal.key and thread-store.key (0600, same uid): Landlock is the only barrier, so a
    granted tree that reaches it (``--extra-sys-path``, a target prefix, a repo path, or ``HLITH_STATE_DIR`` placed inside one) would let
    confined target code read the verifier key and print it into an outcome. Compared on canonical paths, refused by name."""
    # the env/default root AND every root a LocalHostState of this process was built with (explicit roots, the UI's <ui>/host).
    # No import here: this module is also loaded standalone by file path (hlith/sandbox.py shim), so state.py registers INTO it.
    env_dir = os.environ.get("HLITH_STATE_DIR")
    xdg = os.environ.get("XDG_STATE_HOME")
    default = env_dir or os.path.join(xdg or os.path.join(os.path.expanduser("~"), ".local", "state"), "hlith")  # = state.default_state_root
    roots = sorted({os.path.realpath(default), *LIVE_STATE_ROOTS})
    for g in sorted({*spec.get("ro", []), *spec.get("rw", []), *spec.get("ro_bind", [])}):
        if g in ("/dev/null", "/dev/zero", "/dev/urandom", "/proc"):
            continue
        gc = os.path.realpath(g)
        for state in roots:
            if gc == state or state.startswith(gc.rstrip("/") + "/") or gc.startswith(state.rstrip("/") + "/"):
                raise GrantError(f"grant {g} overlaps the hlith host state root {state} (holds the verifier and journal keys): "
                                 "refusing to confine; keep the state directory outside every granted path")


def vet_grants(spec: dict) -> None:
    """Every ro / rw / ro_bind tree of a spec must be free of sockets, FIFOs and device nodes.

    A pathname AF_UNIX socket under a read-only grant stays connectable (connect is not a write), which let a
    confined worker hand its writable fds to an outside process. This runs inside run_confined, so no caller
    (worker, differential, z3, feedback probes, Layer 1 resume) can forget it. System roots are the host's;
    the interpreter prefixes are vetted once per TTL, everything else on every call."""
    refuse_rw_over_ro_bind(spec)
    refuse_grant_over_host_state(spec)
    prefixes = {sys.prefix, sys.base_prefix}
    budget = [_MAX_GRANT_ENTRIES]
    now = time.monotonic()
    for root in sorted({*spec.get("ro", []), *spec.get("rw", []), *spec.get("ro_bind", [])}):
        if root in ("/dev/null", "/dev/zero", "/dev/urandom") or any(root == r or root.startswith(r + "/") for r in _SYSTEM_ROOTS):
            continue
        if root in prefixes and now - _prefix_ok.get(root, -1e9) < _PREFIX_TTL:
            continue
        try:
            _vet_tree(root, budget)
        except FileNotFoundError:
            continue
        if root in prefixes:
            _prefix_ok[root] = now


@dataclass(frozen=True)
class Profile:
    ro: tuple[str, ...] = ()
    rw: tuple[str, ...] = ()
    ro_bind: tuple[str, ...] = ()
    net: bool = False

    def spec(self) -> dict:
        prefixes = sorted({sys.prefix, sys.base_prefix})
        return {
            "ro": sorted(set(_SYSTEM_RO) | set(prefixes) | {str(Path(p).resolve()) for p in self.ro}),
            "rw": sorted({str(Path(p).resolve()) for p in self.rw} | {"/dev/null"}),
            "ro_bind": sorted(str(Path(p).resolve()) for p in self.ro_bind),
            "net": self.net,
        }

    @property
    def sha256(self) -> str:
        return hashlib.sha256(json.dumps(self.spec(), sort_keys=True).encode()).hexdigest()


_REAP_PREFIX, _REAP_AGE_S, _REAP_CAP = "hlith-run-", 3600, 50


def reap_stale_run_dirs(parent: str | None = None) -> int:
    """Lazy, bounded reaper for per-run dirs whose OWNING supervisor was SIGKILLed (TemporaryDirectory cannot clean
    after that). Only direct children named hlith-run-*, real directories (never symlinks), owned by this uid, mtime
    older than an hour; at most 50 rmdir attempts per call. rmdir removes only EMPTY dirs, so a live run's tree is
    never touched. Nothing else (hlith-root-*: maintainer-gated purge) is considered. Errors: one stderr line, never
    fatal. Returns the number removed."""
    import errno
    import tempfile
    import time

    parent = parent or tempfile.gettempdir()
    uid, now, tried, removed, errs = os.getuid(), time.time(), 0, 0, []
    try:
        pfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as e:
        sys.stderr.write(f"hlith: run-dir reaper: cannot open {parent}: {e.strerror}\n")
        return 0
    try:
        with os.scandir(pfd) as it:
            for ent in it:
                if tried >= _REAP_CAP:
                    break
                if not ent.name.startswith(_REAP_PREFIX):
                    continue
                try:
                    st = ent.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or now - st.st_mtime < _REAP_AGE_S:
                    continue
                tried += 1
                try:
                    os.rmdir(ent.name, dir_fd=pfd)
                    removed += 1
                except OSError as e:
                    if e.errno not in (errno.ENOTEMPTY, errno.EEXIST, errno.ENOENT):
                        errs.append(f"{ent.name}: {e.strerror}")
    except OSError as e:
        errs.append(f"scan: {e.strerror}")
    finally:
        os.close(pfd)
    if errs:
        sys.stderr.write(f"hlith: run-dir reaper: {len(errs)} error(s), first {errs[0]}\n")
    return removed


def run_confined(
    argv: list[str], profile: Profile, *, cwd: str | None = None, timeout: float = 60, env: dict | None = None
) -> subprocess.CompletedProcess:
    """close_fds=True (default) scrubs every inherited descriptor except 0/1/2.

    Raises GrantError before anything starts if a granted tree holds a socket/FIFO/device (finding 24)."""
    vet_grants(profile.spec())
    import tempfile

    reap_stale_run_dirs()

    # review: the launcher's mount-point dir lives in a per-run tree THIS process removes after reaping the launcher, so
    # even an uncatchable kill of the launcher before pivot_root leaves nothing (not part of the profile hash)
    with tempfile.TemporaryDirectory(prefix="hlith-run-") as own:
        boundary_path = os.path.join(own, "boundary.json")
        cmd = [
            sys.executable,
            "-I",
            _LAUNCHER,
            json.dumps({**profile.spec(), "root_parent": own, "boundary_status": boundary_path}),
            "--",
            *argv,
        ]
        cp = subprocess.run(
            cmd, cwd=cwd, timeout=timeout, capture_output=True, text=True, close_fds=True, stdin=subprocess.DEVNULL,
            env=env if env is not None else {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
        )
        bf = _read_boundary_failure(boundary_path, cp.returncode)
        return ConfinedProcess(cp.args, cp.returncode, stdout=cp.stdout, stderr=cp.stderr, boundary_failure=bf)
