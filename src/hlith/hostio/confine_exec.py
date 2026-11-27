# SPDX-License-Identifier: Apache-2.0
"""Kernel confinement launcher. Self-contained: run as a script, never imported.

    python -I _confine.py '<json spec>' -- argv...

Order matters: new user+mount namespace, read-only bind of protected paths
(covers metadata writes that Landlock does not: chmod, utimes, xattr), drop
all capabilities, no_new_privs, Landlock ruleset (denies mount/umount and all
file writes outside rw paths, plus TCP bind/connect; scopes abstract unix
sockets and signals; pathname unix sockets and UDP are NOT Landlock rules here,
see the comment in landlock()), then exec.
Fails closed with exit 4 if any layer cannot be established.
"""

import ctypes
import errno
import json
import os
import sys

EXIT_BOUNDARY = 4

SYS_CREATE, SYS_ADD, SYS_RESTRICT = 444, 445, 446
FS = {  # access bit -> minimum ABI
    1 << 0: 1, 1 << 1: 1, 1 << 2: 1, 1 << 3: 1, 1 << 4: 1, 1 << 5: 1, 1 << 6: 1,
    1 << 7: 1, 1 << 8: 1, 1 << 9: 1, 1 << 10: 1, 1 << 11: 1, 1 << 12: 1,
    1 << 13: 2, 1 << 14: 3, 1 << 15: 5,
}
READ = (1 << 0) | (1 << 2) | (1 << 3)  # execute, read file, read dir
NET_BIND, NET_CONNECT = 1 << 0, 1 << 1

MS_RDONLY, MS_NOSUID, MS_NODEV, MS_REMOUNT, MS_BIND, MS_REC = 1, 2, 4, 32, 4096, 16384


_ROOT = None  # (parent dir fd, name) of the launcher's mount-point dir while the LAUNCHER side owns it
_BOUNDARY_FD = None  # host-private O_CLOEXEC status fd (closed before execvp; unreachable by target code)


def _write_boundary(code: str, stage: str, msg: str, errno_val: int | None = None) -> None:
    """Write ONE typed host boundary record to the host-private O_CLOEXEC status file (never visible to target code)."""
    global _BOUNDARY_FD
    fd = _BOUNDARY_FD
    if fd is None:
        return
    _BOUNDARY_FD = None
    try:
        payload = json.dumps(
            {"code": code, "stage": stage, "errno": errno_val, "detail": str(msg)[:300]},
            sort_keys=True,
        ).encode("utf-8", "replace") + b"\n"
        os.write(fd, payload)
    except OSError:
        pass
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def die(msg: str, *, code: str = "confinement-setup-failed", stage: str = "launcher", errno_val: int | None = None) -> None:
    _write_boundary(code, stage, msg, errno_val)
    sys.stderr.write(f"hlith-confine: {msg}\n")
    release_root()
    os._exit(EXIT_BOUNDARY)


def release_root() -> None:
    """Remove the mount-point dir from the HOST filesystem, once. Path lookups are useless here: after the child's
    pivot_root every process of the mount namespace, the launcher included, has the tmpfs as '/', so the dir is
    reached only through the parent-directory fd opened before the namespaces existed. Unexpected errors are
    reported, never swallowed (expected: ENOENT/EINVAL from the path umount once the child has pivoted)."""
    global _ROOT
    if _ROOT is None:
        return
    pfd, name, path = _ROOT
    _ROOT = None
    if libc.umount2(os.fsencode(path), 2) != 0 and ctypes.get_errno() not in (2, 22):  # pre-pivot tmpfs only
        e = ctypes.get_errno()
        sys.stderr.write(f"hlith-confine: cleanup umount {path}: errno {e} {os.strerror(e)}\n")
    try:
        os.rmdir(name, dir_fd=pfd)
    except FileNotFoundError:
        pass
    except OSError as e:
        sys.stderr.write(f"hlith-confine: cleanup rmdir {path}: errno {e.errno} {e.strerror}\n")
    finally:
        os.close(pfd)


libc = ctypes.CDLL(None, use_errno=True)


def sc(*a):
    r = libc.syscall(*a)
    if r < 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e))
    return r


class RulesetAttr(ctypes.Structure):
    _fields_ = [("fs", ctypes.c_uint64), ("net", ctypes.c_uint64), ("scoped", ctypes.c_uint64)]


class PathBeneath(ctypes.Structure):
    _pack_ = 1
    _layout_ = "ms"
    _fields_ = [("allowed", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


ST_TO_MS = {2: MS_NOSUID, 4: MS_NODEV, 8: 8, 1024: 1024, 2048: 2048, 4096: 4096}  # statvfs flag -> mount flag


def mount(src, dst, fstype, flags, data=None) -> None:
    if libc.mount(os.fsencode(src) if src else None, os.fsencode(dst), fstype, flags, data) != 0:
        err = ctypes.get_errno()
        die(f"mount {src or fstype} -> {dst}: {os.strerror(err)}", code="mount-namespace-failed", stage="build_root", errno_val=err)


def bind_into(root: str, path: str, ro: bool) -> None:
    """Make ``path`` appear at the same absolute path inside the new root, nothing else."""
    if not os.path.exists(path):
        return
    dst = root + path
    if os.path.isdir(path):
        os.makedirs(dst, exist_ok=True)
    else:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if not os.path.exists(dst):
            open(dst, "w").close()
    mount(path, dst, None, MS_BIND | MS_REC)
    if ro:
        keep = 0
        for bit, ms in ST_TO_MS.items():  # locked flags must be carried or the remount is refused
            if os.statvfs(dst).f_flag & bit:
                keep |= ms
        nodev = 0 if path.startswith("/dev/") else MS_NODEV  # device nodes must stay usable (urandom, null)
        mount(None, dst, None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | nodev | MS_REC | keep)


def _may_synthesize_hosts(spec: dict, root: str) -> bool:
    """Only in an isolated network namespace, and only when no grant reaches /etc (a file written under a bind mount would land on the host)."""
    if spec.get("net", False) or os.path.islink(root + "/etc") or os.path.lexists(root + "/etc/hosts"):
        return False
    for key in ("ro", "rw", "ro_bind"):
        for granted in spec.get(key, []) or []:
            real = os.path.realpath(granted)
            # a bind of /etc (or of a parent, or of the name file itself) would make the write land on the host; other files under /etc do not
            if any(p in ("/", "/etc", "/etc/hosts") for p in (os.path.normpath(granted), real)):
                return False
    return not os.path.ismount(root + "/etc")


def build_root(spec: dict, root: str) -> None:
    """A tmpfs root holding only the granted paths and a private /proc, then pivot into it.
    Paths outside the grant do not exist (ENOENT), so stat/readdir/proc cannot disclose them."""
    mount("tmpfs", root, b"tmpfs", MS_NOSUID | MS_NODEV, b"size=1m,mode=755")
    ro = [p for p in spec.get("ro", []) if p != "/proc"]
    rw = spec.get("rw", [])
    ro_bind = spec.get("ro_bind", [])
    for p in ro_bind:
        if not os.path.exists(p):
            die(f"ro_bind path missing: {p}")

    def canonical(p: str) -> str:  # `..`, `.`, `//` and symlinked ancestors resolved; a grant that cannot be resolved is refused
        try:
            return os.path.realpath(p, strict=True)  # no normpath first: it would collapse `link/..` before the link resolves
        except (OSError, ValueError) as exc:
            die(f"grant path cannot be canonicalized: {p} ({exc})")
            raise  # unreachable: die() exits

    rw_c = [(r, canonical(r)) for r in rw]
    for p in ro_bind:  # same rule as confinement.refuse_rw_over_ro_bind, on canonical paths, for a spec that did not come through run_confined
        pc = canonical(p)
        for r, rc in rw_c:
            if pc == rc or pc.startswith(rc.rstrip("/") + "/") or rc.startswith(pc.rstrip("/") + "/"):  # disjoint, either direction
                die(f"writable grant {r} overlaps read-only-bound path {p} (ro_bind)")
    for p in sorted(set(ro) | set(ro_bind), key=len):
        bind_into(root, p, True)
    for p in sorted(rw, key=len):
        bind_into(root, p, False)
    if _may_synthesize_hosts(spec, root):  # name resolution for localhost only, never over or into anything that was granted
        os.makedirs(root + "/etc", exist_ok=True)
        with open(root + "/etc/hosts", "w") as f:
            f.write(_SYNTHESIZED + "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n")
        if not os.path.lexists(root + "/etc/nsswitch.conf"):
            with open(root + "/etc/nsswitch.conf", "w") as f:
                f.write(_SYNTHESIZED + "hosts: files\n")
    os.makedirs(root + "/proc", exist_ok=True)
    mount("proc", root + "/proc", b"proc", MS_NOSUID | MS_NODEV | 8)  # fresh procfs of OUR pid namespace
    mount(None, root, None, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
    cwd = os.getcwd()
    os.chdir(root)
    if libc.syscall(155, b".", b".") != 0:  # pivot_root(".", ".")
        err = ctypes.get_errno()
        die(f"pivot_root: {os.strerror(err)}", code="mount-namespace-failed", stage="build_root", errno_val=err)
    if libc.umount2(b".", 2) != 0:  # MNT_DETACH the old root
        err = ctypes.get_errno()
        die(f"umount old root: {os.strerror(err)}", code="mount-namespace-failed", stage="build_root", errno_val=err)
    os.chdir("/")
    try:
        os.chdir(cwd)
    except OSError:
        pass


_NAME_FILES = ("/etc/hosts", "/etc/nsswitch.conf")
_SYNTHESIZED = "# hlith: synthesized for name resolution only\n"


def synthesized_name_files() -> list[str]:
    """The name-resolution files THIS confinement wrote (marker on the first line); a granted or host file never matches."""
    found = []
    for path in _NAME_FILES:
        try:
            with open(path) as f:
                if f.readline() == _SYNTHESIZED:
                    found.append(path)
        except OSError:
            pass
    return found


def enter_namespaces(net: bool = False) -> None:
    """net=False also unshares the network namespace: a fresh, empty one (loopback down, no interfaces),
    so no datagram/raw/AF_UNIX-by-address path to the host exists. Landlock's TCP rules stay as defence
    in depth; they never covered UDP (finding 23). Landlock-only children inherit their parent's netns.
    `localhost` RESOLVES (synthesized hosts file) but nothing can be sent: bringing `lo` up would let confined processes exchange datagrams."""
    uid, gid = os.getuid(), os.getgid()
    os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS | os.CLONE_NEWPID | (0 if net else os.CLONE_NEWNET))
    with open("/proc/self/setgroups", "w") as f:
        f.write("deny")
    with open("/proc/self/uid_map", "w") as f:
        f.write(f"{uid} {uid} 1")
    with open("/proc/self/gid_map", "w") as f:
        f.write(f"{gid} {gid} 1")
    if libc.mount(None, b"/", None, MS_REC | (1 << 18), None) != 0:  # MS_PRIVATE: nothing leaks to the host
        err = ctypes.get_errno()
        die(f"cannot make mounts private: {os.strerror(err)}", code="mount-namespace-failed", stage="enter_namespaces", errno_val=err)


def drop_caps() -> None:
    for cap in range(0, 64):
        if libc.prctl(24, cap, 0, 0, 0) != 0:  # PR_CAPBSET_DROP
            err = ctypes.get_errno()
            if err == 22:  # EINVAL: beyond last cap
                break
            die("cannot drop capability bounding set", code="drop-caps-failed", stage="drop_caps", errno_val=err)


def landlock(ro: list[str], rw: list[str], allow_net: bool) -> None:
    try:
        abi = sc(SYS_CREATE, None, 0, 1)
    except OSError as e:
        die(f"Landlock syscall unavailable: {e}", code="landlock-unavailable", stage="landlock", errno_val=e.errno)
        raise  # unreachable
    if abi < 1:
        die("Landlock unavailable", code="landlock-unavailable", stage="landlock")
    fs_mask = 0
    for bit, minabi in FS.items():
        if abi >= minabi:
            fs_mask |= bit
    # ABI 6+: scope ABSTRACT unix sockets and signals to this domain, so the worker cannot connect to a host
    # abstract socket (fd passing) or signal host processes. This does NOT mediate PATHNAME unix sockets:
    # that is LANDLOCK_ACCESS_FS_RESOLVE_UNIX (ABI 9), which is not requested here; pathname sockets are kept
    # out by the mount view (only granted paths exist) and the special-file vetting of grants. UDP is not
    # mediated by these rules either (UDP rights need ABI 10); with net=False it is stopped by the empty network
    # namespace (loopback down), not by Landlock.
    if abi < 6:  # fail closed: below ABI 6 fd passing over abstract sockets and host signals are open
        die(f"Landlock ABI {abi} < 6: socket/signal scoping unavailable", code="landlock-abi-too-old", stage="landlock")
    scoped = 3
    attr = RulesetAttr(fs_mask, 0 if (allow_net or abi < 4) else (NET_BIND | NET_CONNECT), scoped)
    size = 8 if abi < 4 else (16 if abi < 6 else 24)
    try:
        rfd = sc(SYS_CREATE, ctypes.byref(attr), size, 0)
    except OSError as e:
        die(f"Landlock ruleset creation failed: {e}", code="landlock-setup-failed", stage="landlock", errno_val=e.errno)
        raise  # unreachable
    ro_mask = READ & fs_mask

    def add(path: str, access: int) -> None:
        try:
            fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError:
            return
        try:
            # directories get full access bits; files only file-applicable bits
            if not os.path.isdir(path):
                access &= (1 << 0) | (1 << 1) | (1 << 2) | (1 << 14)
            sc(SYS_ADD, rfd, 1, ctypes.byref(PathBeneath(access, fd)), 0)
        finally:
            os.close(fd)

    try:
        for p in [*ro, *synthesized_name_files()]:
            add(p, ro_mask)
        # Writable areas may hold data, not rendezvous points: no sockets, FIFOs or device nodes can be
        # created there, so a worker cannot publish a pathname socket for a host-side process to
        # pass descriptors through (abstract sockets are already scoped out above). Connecting to an EXISTING
        # pathname socket is not a Landlock right below ABI 9 and is not requested.
        no_special = (1 << 6) | (1 << 9) | (1 << 10) | (1 << 11)
        for p in rw:
            add(p, fs_mask & ~no_special)
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
            err = ctypes.get_errno()
            die("no_new_privs failed", code="landlock-setup-failed", stage="landlock", errno_val=err)
        sc(SYS_RESTRICT, rfd, 0)
    except OSError as e:
        die(f"Landlock restrict failed: {e}", code="landlock-setup-failed", stage="landlock", errno_val=e.errno)
    finally:
        os.close(rfd)


def landlock_only() -> None:
    """Narrow an already-confined process further, for a child of a trusted driver.

        python -I _confine.py --landlock-only '<json spec>' -- argv...

    No namespaces or mounts (a Landlock domain cannot mount, and domains only ever stack and narrow):
    only a new, stricter Landlock ruleset (+ scoped signals/abstract sockets, no_new_privs), then exec.
    The spec's ro/rw lists must be subsets of what the driver itself was granted."""
    if len(sys.argv) < 5 or sys.argv[3] != "--":
        die("usage: _confine.py --landlock-only SPEC -- argv...")
    spec = json.loads(sys.argv[2])
    try:
        landlock(spec.get("ro", []), spec.get("rw", []), False)
    except OSError as e:
        die(f"{e}")
    os.closerange(3, 65536)  # no driver descriptor (checkpoint db, pipes) crosses the exec
    os.execvp(sys.argv[4], sys.argv[4:])


# Catchable termination signals the LAUNCHER handles. They are BLOCKED from before the mount-point dir exists until
# the launcher knows its child, so none can take the default action in between (review: SIGINT before the handler
# was installed left the dir). Not handled, documented: SIGKILL/SIGSTOP (uncatchable: the supervisor passes
# spec.root_parent inside a per-run tree it removes, sandbox.run_confined); SIGPIPE (ignored: the launcher writes
# only diagnostics to stderr); SIGABRT/SIGSEGV/SIGBUS (internal faults of the launcher itself, not delivered by
# supervisors; root_parent covers them like SIGKILL).
_CHILD = None


def _stage(name: str) -> None:
    """Test seam: stop at a named lifecycle stage so a test can deliver a signal THERE (deterministic, no timing).
    Only the launcher's own environment can set it; run_confined passes a fixed env without it."""
    if os.environ.get("HLITH_CONFINE_STOP_AT") == name:
        os.kill(os.getpid(), 19)  # SIGSTOP: cannot be blocked; the test sends its signal, then SIGCONT


def _on_signal(signum, _frame) -> None:
    if _CHILD:
        try:
            os.kill(_CHILD, 9)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(_CHILD, 0)
        except ChildProcessError:
            pass
    release_root()
    os._exit(128 + signum)


def _supervisor_gone(supervisor: int) -> bool:
    """case: the launcher's parent (the supervising engine) may die by an uncatchable SIGKILL, which no handler can
    answer. getppid changes on reparenting when the parent PROCESS is gone (PDEATHSIG would be wrong here: it fires when the
    parent THREAD that spawned us exits). No thread can do this check: after unshare(CLONE_NEWPID) a CLONE_THREAD clone fails
    (EINVAL), so the launcher's main thread polls between its waits."""
    return os.getppid() != supervisor


DEFAULT_AS_LIMIT_BYTES = 8 * 1024 ** 3  # RLIMIT_AS for every confined process unless the spec says otherwise


def _limit_address_space(spec: dict) -> None:
    """Bound the worker's virtual memory before exec. With vm.overcommit_memory=1 the kernel never refuses an allocation, so target code
    such as ``"x" * 10**12`` would otherwise fill host RAM instead of raising MemoryError. ``as_limit_bytes`` in the spec overrides the
    default; 0 (or None) means explicitly unlimited. A pre-existing lower limit is kept (the limit can only be tightened here)."""
    import resource

    limit = spec.get("as_limit_bytes", DEFAULT_AS_LIMIT_BYTES)
    if not limit:
        return
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
        raise ValueError(f"as_limit_bytes must be a non-negative integer: {limit!r}")
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    for cur in (soft, hard):
        if cur != resource.RLIM_INFINITY and cur < limit:
            limit = cur
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def main() -> None:
    import signal
    import tempfile

    global _ROOT, _CHILD, _BOUNDARY_FD
    if len(sys.argv) > 1 and sys.argv[1] == "--landlock-only":
        landlock_only()
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        die("usage: _confine.py SPEC -- argv...")
    sigs = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT)
    signal.pthread_sigmask(signal.SIG_BLOCK, sigs)  # held pending until the launcher can clean up for them
    for sig in sigs:
        signal.signal(sig, _on_signal)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    _stage("pre_mkdtemp")
    spec = json.loads(sys.argv[1])
    argv = sys.argv[3:]
    parent = spec.get("root_parent")  # a private per-run dir the supervisor removes when it reaps the launcher
    if parent is not None and not (isinstance(parent, str) and os.path.isabs(parent) and os.path.isdir(parent)):
        die(f"root_parent must be an existing absolute directory: {parent!r}")
    bstatus = spec.get("boundary_status")
    if isinstance(bstatus, str) and parent is not None and os.path.dirname(bstatus) == parent:
        try:
            _BOUNDARY_FD = os.open(bstatus, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        except OSError as e:
            die(f"cannot open boundary status channel: {e}", code="confinement-setup-failed", stage="launcher", errno_val=e.errno)
    if parent is None:
        sys.stderr.write("hlith-confine: no root_parent: mount point in the global temp dir (uncatchable kills "
                         "before pivot can leave it)\n")
    root = tempfile.mkdtemp(prefix="hlith-root-", dir=parent)
    _ROOT = (os.open(os.path.dirname(root), os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC), os.path.basename(root), root)
    _stage("post_mkdtemp")
    try:
        enter_namespaces(bool(spec.get("net", False)))
    except OSError as e:
        code = "userns-unavailable" if e.errno in (errno.EPERM, errno.EACCES, errno.ENOSYS, errno.EINVAL, errno.EUSERS) else "namespace-setup-failed"
        die(f"user/mount namespace setup failed: {e}", code=code, stage="enter_namespaces", errno_val=e.errno)
    _stage("pre_fork")
    pending = set(signal.sigpending()) & set(sigs)
    if pending:  # a termination request arrived during setup: honour it before any child exists
        _on_signal(int(min(pending)), None)
    rd, wr = os.pipe()
    supervisor = os.getppid()
    pid = os.fork()  # the child is pid 1 of the new pid namespace
    if pid:
        if _BOUNDARY_FD is not None:
            try:
                os.close(_BOUNDARY_FD)
            except OSError:
                pass
            _BOUNDARY_FD = None
        _CHILD = pid
        os.close(wr)
        _stage("post_fork")
        signal.pthread_sigmask(signal.SIG_UNBLOCK, sigs)  # pending signals are delivered to _on_signal now
        import select
        import time

        orphaned = False

        def _check_supervisor() -> None:  # case: supervisor gone -> SIGKILL the namespace init (once)
            nonlocal orphaned
            if not orphaned and _supervisor_gone(supervisor):
                orphaned = True
                try:
                    os.kill(pid, 9)
                except ProcessLookupError:
                    pass

        while not select.select([rd], [], [], 0.25)[0]:  # readable once the child has pivoted (or EOF if it died first)
            _check_supervisor()
        try:
            os.read(rd, 1)
        except OSError:
            pass
        os.close(rd)
        release_root()  # the mount point is not needed after pivot_root: gone before the worker runs
        _stage("post_pivot")
        try:
            pidfd = os.pidfd_open(pid)  # readable the moment the child exits: no polling latency on the normal path
        except (AttributeError, OSError):
            pidfd = None
        while True:
            done, st = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            _check_supervisor()
            if pidfd is not None:
                select.select([pidfd], [], [], 0.25)  # wakes at once on exit; at most 0.25 s between supervisor checks
            else:
                time.sleep(0.01)
        if pidfd is not None:
            os.close(pidfd)
        os._exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 128 + os.WTERMSIG(st))
    _ROOT = None  # the launcher side owns the dir; a child die() must not touch it
    os.close(rd)
    for sig in (*sigs, signal.SIGPIPE):
        signal.signal(sig, signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, sigs)  # the mask is inherited across exec: the worker gets a clean one
    try:
        libc.prctl(1, 9, 0, 0, 0)  # PR_SET_PDEATHSIG=SIGKILL: no orphaned worker if the launcher is killed
        build_root(spec, root)
        os.write(wr, b"1")
        os.close(wr)
        drop_caps()
        landlock(spec.get("ro", []), spec.get("rw", []), spec.get("net", False))
    except OSError as e:
        die(f"{e}")
    try:
        _limit_address_space(spec)
    except (OSError, ValueError) as e:
        die(f"cannot set the address-space limit: {e}", code="rlimit-setup-failed", stage="rlimit", errno_val=getattr(e, "errno", None))
    # Confinement succeeded: close the host-private boundary status fd (0 bytes written) along with all fds >= 3 before execvp.
    _BOUNDARY_FD = None
    os.closerange(3, 65536)  # nothing inherited beyond stdio crosses the exec
    os.execvp(argv[0], argv)


if __name__ == "__main__":
    main()
