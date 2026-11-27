# SPDX-License-Identifier: Apache-2.0
"""Adversarial independent escape & bypass attacks against hlith sandbox and gate.

Covers attack vectors beyond tests/test_sandbox_escapes.py:
  1. Abstract UNIX domain socket connection & SCM_RIGHTS fd passing (FINDING 1: sandbox escape)
  2. Signal injection via unshared PID namespace / matching UID (FINDING 2: supervisor kill)
  3. Target repository git hook execution during gate.land() (FINDING 3: host code exec)
  4. Target repository git config fsmonitor execution during gate.land() (FINDING 4: host code exec)
  5. Target directory symlink swap race before gate apply (FINDING 5: wrong repo mutated)
  6. TOCTOU index injection between check and commit (FINDING 6: unverified state landed)
  7. Patch path traversal with ../ (DEFENSE HOLDS: git apply rejects)
  8. Patch symlink write-through (DEFENSE HOLDS: git apply rejects)
  9. /proc/self/cwd write escape (DEFENSE HOLDS: Landlock/ro-bind rejects)
 10. ptrace attach on supervisor (DEFENSE HOLDS: kernel userns check rejects)
 11. io_uring setup availability audit (AUDIT: io_uring_setup succeeds in sandbox)
 12. Real codebase evaluation on psf/requests @0e322af (REAL-CODE SUITE)
 13. Filesystem UNIX domain socket SCM_RIGHTS fd passing in rw stage (DEFENSE HOLDS: no_special denies MAKE_SOCK)
 14. Gate landing symlink pointing to target .git directory (DEFENSE HOLDS: patch_violations norm check)
 15. Gate landing patch modifying .hlith metadata directory (DEFENSE HOLDS: patch_violations _RESERVED check)
 16. Named pipe (FIFO) in repository tree hangs AST parser (FINDING 10: routed to review)
 17. Gate landing symlink escaping repository root (DEFENSE HOLDS: patch_violations norm check)
 18. Stage repository git config isolation during diff generation (DEFENSE HOLDS)
 19. Inherited TTY stdin IOCTL TIOCSTI command injection (DEFENSE HOLDS: stdin=DEVNULL)
 20. Information disclosure of supervisor cmdline & fds via host /proc (FINDING 12: info leak)
 21. Stat and filesystem topology disclosure outside sandbox (FINDING 13: metadata leak)
 22. Commit header CRLF injection in proposer_id forges landing key (FINDING 14: closed by design review)
 23. C-quoted diff headers bypass patch_violations reserved path checks (FINDING 15: closed by design review)
 24. Circular symlink loop landing causes ELOOP DoS in downstream tools (FINDING 16: intra-patch cycles closed by design review)
 25. Supervisor crash on non-UTF-8 bytes in stage diff (FINDING 17: UnicodeDecodeError DoS)
 26. Supervisor crash on deep directory trees exceeding PATH_MAX (FINDING 18: ENAMETOOLONG DoS)
 27. Gate permits symlink cycles closing through existing repository symlinks (FINDING 19: cross-commit ELOOP DoS)
 28. Child worker attempt to signal/kill driver PID 1 (DEFENSE HOLDS: Landlock scoped signals deny)
 29. Broad network surface attack under net=False: UDP v4/v6, AF_UNIX dgram, AF_PACKET, raw, abstract unix, netlink, loopback, NSCD, io_uring, /proc/net (FINDING 23: closed by review CLONE_NEWNET + Landlock)
 30. Residual pathname AF_UNIX socket in granted path reachable under net=False (FINDING 24 RESIDUAL: netns does not scope pathname sockets)
"""

from __future__ import annotations

import array
import ctypes
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from hlith.gate import head_tree, land, target_identity
from hlith.runtime import EffectRejected, run_worker
from hlith.sandbox import GrantError, Profile, run_confined
from hlith.types import (
    BoundedEvidence,
    CheckProvenance,
    GateOutcome,
    Obligation,
    ObligationSet,
    ProposedEffect,
    Verdict,
)

PROV = CheckProvenance("adversarial_harness", "ab" * 32, True, False, "cd" * 32, 0)
EV = BoundedEvidence(12, "adversarial attack vectors", "unexplored physical memory")


def _held(oid: str = "o1") -> Obligation:
    return Obligation(oid, "m.f", "claim", Verdict.HELD, evidence=EV, provenance=PROV, account_bound=True)


def _init_git_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "-C", str(path), "init", "-q", "-b", "main"], check=True)
    (path / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(path),
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-q",
            "-m",
            "base",
        ],
        check=True,
    )
    return path


# ============================================================================
# FINDINGS (Vulnerabilities in sandbox.py / _confine.py / gate.py)
# ============================================================================


def test_abstract_unix_socket_fd_passing_mutates_target(tmp_path):
    """FINDING 1: SCM_RIGHTS FD Passing Over Abstract UNIX Domain Socket.

    Root Cause: _confine.py does not unshare the network namespace (CLONE_NEWNET),
    and Landlock's network rules only constrain TCP (AF_INET/AF_INET6), not AF_UNIX.
    A confined worker can connect to an abstract UNIX socket on the host, receive an
    open write descriptor to the target repository via SCM_RIGHTS, and write to target
    because Landlock does not mediate write() calls on already-open descriptors.
    """
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()
    secret = target / "secret.txt"
    secret.write_text("ORIGINAL_SECRET\n")

    leaked_fd = os.open(str(secret), os.O_RDWR)
    sock_addr = bytes([0]) + f"hlith_test_fd_pass_{os.getpid()}".encode()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(sock_addr)
    server.listen(1)

    probe = stage / "probe.py"
    probe.write_text(f"""import socket, array, os
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(bytes([0]) + {sock_addr[1:]!r})
fds = array.array('i')
msg, ancdata, flags, addr = s.recvmsg(1024, socket.CMSG_LEN(fds.itemsize))
for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
target_fd = fds[0]
os.write(target_fd, b"PWNED_VIA_SCM_RIGHTS\\n")
os.close(target_fd)
""")

    def serve():
        try:
            conn, _ = server.accept()
            anc = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [leaked_fd]).tobytes())]
            conn.sendmsg([b"FD"], anc)
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    try:
        prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
        cp = run_confined([sys.executable, str(probe)], prof)
        # The kernel refuses the connect (via CLONE_NEWNET netns isolation -> ConnectionRefusedError,
        # or Landlock abstract-socket scope -> PermissionError), so the worker exits non-zero;
        # the invariant is the target, asserted below.
        assert "PermissionError" in cp.stderr or "ConnectionRefusedError" in cp.stderr, f"expected kernel denial, got: {cp.stderr[-300:]}"
    finally:
        os.close(leaked_fd)
        server.close()
        t.join(timeout=2)

    # Invariant: Target must remain unmutated by the confined worker.
    # Repro: This fails because secret.txt was overwritten with PWNED_VIA_SCM_RIGHTS.
    assert secret.read_text() == "ORIGINAL_SECRET\n", (
        "FINDING 1: Confined worker escaped sandbox via abstract UNIX domain socket SCM_RIGHTS!"
    )


def test_confined_worker_can_signal_host_processes(tmp_path):
    """FINDING 2: Signal Injection into Host Processes via Unshared PID Namespace.

    Root Cause: _confine.py unshares CLONE_NEWUSER and CLONE_NEWNS, but NOT
    CLONE_NEWPID. The mapped UID inside the sandbox equals the host UID.
    Linux check_kill_permission permits signals between processes with matching UIDs.
    A confined worker can send arbitrary signals (SIGKILL, SIGSTOP) to supervisor
    or host processes.
    """
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()

    victim = subprocess.Popen(["sleep", "60"])
    try:
        probe = stage / "probe.py"
        probe.write_text(f"""import os, signal
try:
    os.kill({victim.pid}, signal.SIGKILL)
    print("SIGNAL_SENT")
except Exception as e:
    print("SIGNAL_FAILED:", e)
""")
        prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
        cp = run_confined([sys.executable, str(probe)], prof)
        assert cp.returncode == 0, cp.stderr

        # Invariant: Confined worker must not be able to terminate host processes.
        # Repro: This fails because the victim process was killed with SIGKILL (-9).
        victim.poll()
        assert victim.returncode is None, (
            f"FINDING 2: Confined worker killed host process (pid={victim.pid}, exit={victim.returncode})!"
        )
    finally:
        victim.kill()
        victim.wait()


def test_gate_executes_target_git_hooks(tmp_path):
    """FINDING 3: Arbitrary Host Command Execution via Target Repo Git Hooks.

    Root Cause: gate.py runs `git commit` in the unconfined supervisor process
    without passing `--no-verify` or `-c core.hooksPath=/dev/null`. If the target
    repository contains a hook (e.g. .git/hooks/post-commit or pre-commit), the
    supervisor executes it with full host privileges.
    """
    repo = _init_git_repo(tmp_path / "repo")
    pwned_marker = tmp_path / "hook_executed.pwn"

    hook = repo / ".git" / "hooks" / "post-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(f"#!/bin/sh\ntouch {pwned_marker}\n")
    hook.chmod(0o755)

    diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-x = 1
+x = 2
"""
    eff = ProposedEffect(diff, "p")
    tree = head_tree(repo)
    dec = land(repo, eff, ObligationSet((_held(),)), expected_tree=tree, verified_patch_sha256=eff.patch_sha256, expected_identity=target_identity(repo))
    assert dec.outcome is GateOutcome.LANDED

    # Invariant: gate.land() must not execute untrusted hooks from the target repo.
    # Repro: This fails because post-commit executed and created hook_executed.pwn.
    assert not pwned_marker.exists(), (
        "FINDING 3: gate.land() executed arbitrary code from target .git/hooks/post-commit!"
    )


def test_gate_executes_target_git_config(tmp_path):
    """FINDING 4: Arbitrary Host Command Execution via Target Repo Git Config.

    Root Cause: gate.py runs git commands with `-C <target>` without isolating
    the repository configuration. If `<target>/.git/config` contains directives
    such as `core.fsmonitor` or `core.hooksPath`, git invokes external commands
    in the supervisor context.
    """
    repo = _init_git_repo(tmp_path / "repo")
    pwned_marker = tmp_path / "config_executed.pwn"
    tree = head_tree(repo)  # what the operator verified BEFORE the repository config turns hostile
    identity = target_identity(repo)

    with open(repo / ".git" / "config", "a") as f:
        f.write(f"""
[core]
    fsmonitor = "touch {pwned_marker}"
""")

    diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-x = 1
+x = 2
"""
    eff = ProposedEffect(diff, "p")
    # the gate now REFUSES a hostile target (closed-world vet) before any git runs in it: a refusal decision or a boundary RuntimeError are both
    # correct; what must never happen is the configured program running (asserted below), or a landing.
    try:
        decision = land(repo, eff, ObligationSet((_held(),)), expected_tree=tree, verified_patch_sha256=eff.patch_sha256, expected_identity=identity)
        assert getattr(decision.outcome, "value", decision.outcome) != "landed", decision
    except RuntimeError as refusal:
        assert "core.fsmonitor" in str(refusal), refusal

    # Invariant: gate.land() must not execute commands configured in target .git/config.
    # Repro: This fails because fsmonitor command was executed by git status/commit.
    assert not pwned_marker.exists(), (
        "FINDING 4: gate.land() executed arbitrary code from target .git/config fsmonitor!"
    )


def test_gate_symlink_swap_mutates_wrong_repo(tmp_path):
    """FINDING 5: Target Directory Symlink Swap Race.

    Root Cause: gate.py takes `target: Path` and invokes `git -C str(target)`
    without resolving the canonical filesystem path (target.resolve(strict=True)).
    If `target` is a symlink that is swapped between inspection and apply, the
    gate applies and commits changes to an uninspected repository.
    """
    repo1 = _init_git_repo(tmp_path / "repo1")
    repo2 = _init_git_repo(tmp_path / "repo2")
    target_link = tmp_path / "target_link"
    target_link.symlink_to(repo1)

    diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-x = 1
+x = 999
"""
    eff = ProposedEffect(diff, "p")
    expected_tree = head_tree(target_link)
    identity = target_identity(target_link)  # what the supervisor binds at verification

    # Attacker swaps symlink to point to repo2 before gate runs
    target_link.unlink()
    target_link.symlink_to(repo2)

    dec = land(target_link, eff, ObligationSet((_held(),)), expected_tree=expected_tree, verified_patch_sha256=eff.patch_sha256, expected_identity=identity)

    # Invariant: Gate must not land changes into a swapped repository target.
    # Repro: Fails because repo2 was mutated and committed.
    assert (repo2 / "a.py").read_text() == "x = 1\n", (
        "FINDING 5: gate.land() followed a swapped symlink and mutated the wrong repository!"
    )


def test_gate_toctou_index_injection_commits_unverified_file(tmp_path):
    """FINDING 6: TOCTOU Index Injection Between Tree Verification and Commit.

    Root Cause: gate.py verifies `head_tree(target) == expected_tree` and
    `status --porcelain` at the start of land(), but does NOT verify that the
    final committed tree equals the expected applied tree (or that index contains
    only patch files). If a concurrent process stages an unverified file into the
    index before `git commit`, `git commit` includes the unverified file.
    """
    repo = _init_git_repo(tmp_path / "repo")
    unverified_file = repo / "unverified_payload.py"
    unverified_file.write_text("BACKDOOR = True\n")
    # Simulate a concurrent stage right before apply/commit
    subprocess.run(["git", "-C", str(repo), "add", "unverified_payload.py"], check=True)

    diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-x = 1
+x = 2
"""
    eff = ProposedEffect(diff, "p")
    # If the gate proceeds, commit must NOT contain unverified_payload.py
    base_tree = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], capture_output=True, text=True, check=True).stdout.strip()

    # The gate should reject dirty status, but if a concurrent injection occurs:
    # Here status is dirty, so gate returns dirty-target.
    dec = land(repo, eff, ObligationSet((_held(),)), expected_tree=base_tree, verified_patch_sha256=eff.patch_sha256, expected_identity=target_identity(repo))
    assert dec.outcome is GateOutcome.REFUSED
    assert "dirty-target" in dec.blocking


# ============================================================================
# PASSING ATTACKS (Defense Invariants that Hold)
# ============================================================================


def test_gate_refuses_dot_dot_traversal_patch(tmp_path):
    """DEFENSE HOLDS: Patch with ../ path traversal is refused by git apply."""
    repo = _init_git_repo(tmp_path / "repo")
    outside_file = tmp_path / "outside.py"

    diff = """diff --git a/../outside.py b/../outside.py
new file mode 100644
--- /dev/null
+++ b/../outside.py
@@ -0,0 +1 @@
+pwned = True
"""
    eff = ProposedEffect(diff, "p")
    tree = head_tree(repo)
    dec = land(repo, eff, ObligationSet((_held(),)), expected_tree=tree, verified_patch_sha256=eff.patch_sha256, expected_identity=target_identity(repo))
    assert dec.outcome is GateOutcome.REFUSED
    assert dec.exit_status == 4 and dec.blocking  # refused by the policy recheck or by git apply, never landed
    assert not outside_file.exists()


def test_gate_refuses_symlink_writethrough_patch(tmp_path):
    """DEFENSE HOLDS: Patch writing through a symlink to outside dir is refused."""
    repo = _init_git_repo(tmp_path / "repo")
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_file = outside_dir / "pwn.txt"

    diff = f"""diff --git a/link b/link
new file mode 120000
--- /dev/null
+++ b/link
@@ -0,0 +1 @@
+{outside_dir}
\\ No newline at end of file
diff --git a/link/pwn.txt b/link/pwn.txt
new file mode 100644
--- /dev/null
+++ b/link/pwn.txt
@@ -0,0 +1 @@
+pwned
"""
    eff = ProposedEffect(diff, "p")
    tree = head_tree(repo)
    dec = land(repo, eff, ObligationSet((_held(),)), expected_tree=tree, verified_patch_sha256=eff.patch_sha256, expected_identity=target_identity(repo))
    assert dec.outcome is GateOutcome.REFUSED
    assert dec.exit_status == 4 and dec.blocking  # refused by the policy recheck or by git apply, never landed
    assert not outside_file.exists()


def test_proc_self_cwd_write_denied(tmp_path):
    """DEFENSE HOLDS: Writing through /proc/self/cwd is blocked by Landlock & ro-bind."""
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()
    canary = target / "canary.txt"
    canary.write_text("untouched\n")

    probe = stage / "probe.py"
    probe.write_text("""import os
try:
    with open('/proc/self/cwd/canary.txt', 'w') as f:
        f.write('pwned')
    print('ALLOWED')
except OSError:
    print('DENIED')
""")
    prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
    cp = run_confined([sys.executable, str(probe)], prof, cwd=str(target))
    assert cp.returncode == 0, cp.stderr
    assert "DENIED" in cp.stdout
    assert canary.read_text() == "untouched\n"


def test_ptrace_supervisor_denied(tmp_path):
    """DEFENSE HOLDS: ptrace on supervisor process is denied with EPERM by kernel userns check."""
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()

    parent_pid = os.getpid()
    probe = stage / "probe.py"
    probe.write_text(f"""import ctypes
libc = ctypes.CDLL(None, use_errno=True)
PTRACE_ATTACH = 16
r = libc.ptrace(PTRACE_ATTACH, {parent_pid}, 0, 0)
err = ctypes.get_errno() if r != 0 else 0
print(f"PTRACE_RES:{{r}}:ERR:{{err}}")
""")
    prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
    cp = run_confined([sys.executable, str(probe)], prof)
    assert cp.returncode == 0, cp.stderr
    # EPERM (Landlock/yama) or ESRCH: the supervisor is not even visible in the worker's own pid namespace
    assert "PTRACE_RES:-1:ERR:1" in cp.stdout or "PTRACE_RES:-1:ERR:3" in cp.stdout


def test_io_uring_setup_available_in_sandbox(tmp_path):
    """AUDIT: io_uring_setup syscall is accessible inside the sandbox."""
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()

    probe = stage / "probe.py"
    probe.write_text("""import ctypes
libc = ctypes.CDLL(None, use_errno=True)
SYS_io_uring_setup = 425

class io_uring_params(ctypes.Structure):
    _fields_ = [
        ('sq_entries', ctypes.c_uint32), ('cq_entries', ctypes.c_uint32),
        ('flags', ctypes.c_uint32), ('sq_thread_cpu', ctypes.c_uint32),
        ('sq_thread_idle', ctypes.c_uint32), ('features', ctypes.c_uint32),
        ('wq_fd', ctypes.c_uint32), ('resv', ctypes.c_uint32 * 3),
        ('sq_off', ctypes.c_uint8 * 40), ('cq_off', ctypes.c_uint8 * 48),
    ]

p = io_uring_params()
fd = libc.syscall(SYS_io_uring_setup, 2, ctypes.byref(p))
print(f"URING_FD:{fd}")
""")
    prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
    cp = run_confined([sys.executable, str(probe)], prof)
    assert cp.returncode == 0, cp.stderr
    assert "URING_FD:" in cp.stdout


def test_requests_real_repo_confinement_defense_holds(tmp_path):
    """REAL CODE: psf/requests @0e322af confinement test.

    Verifies that a confined worker with read-only access to a clone of psf/requests
    cannot mutate any file in the requests repository.
    """
    requests_src = Path(os.environ.get("HLITH_REQUESTS_ROOT", Path(tempfile.gettempdir()) / "hlith-acc" / "requests"))
    assert requests_src.exists(), "requests clone missing (set HLITH_REQUESTS_ROOT)"

    stage = tmp_path / "stage"
    stage.mkdir()

    # Worker attempts to append to src/requests/__init__.py
    probe = stage / "probe.py"
    probe.write_text(f"""import sys
target_file = '{requests_src / "src" / "requests" / "__init__.py"}'
try:
    with open(target_file, 'a') as f:
        f.write('# ATTACK')
    print('MUTATED')
except OSError:
    print('DENIED')
""")
    prof = Profile(ro=(str(requests_src),), rw=(str(stage),), ro_bind=(str(requests_src),), net=False)
    cp = run_confined([sys.executable, str(probe)], prof)
    assert cp.returncode == 0, cp.stderr
    assert "DENIED" in cp.stdout


# ============================================================================
# ROUND 2 FINDINGS (Additional Vulnerabilities & Attack Vectors)
# ============================================================================


def test_filesystem_unix_socket_fd_passing_mutates_target(tmp_path):
    """FINDING 7: SCM_RIGHTS FD Passing Over Filesystem UNIX Domain Socket.

    Root Cause: Landlock ABI 6+ scopes abstract UNIX sockets (scoped = 3),
    but does NOT mediate filesystem UNIX domain sockets in writable directories.
    Because `stage` is writable (rw=(str(stage),)), the confined worker can bind
    a filesystem socket inside `stage`. A host process can connect to that socket
    and send an open write descriptor to a protected target file via SCM_RIGHTS.
    The worker writes through the descriptor, bypassing confinement.
    """
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()
    secret = target / "secret.txt"
    secret.write_text("ORIGINAL_SECRET\n")

    leaked_fd = os.open(str(secret), os.O_RDWR)
    sock_path = stage / "escape.sock"

    probe = stage / "probe.py"
    probe.write_text("""import socket, array, os, sys
sock_path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(1)
conn, _ = s.accept()
fds = array.array("i")
msg, ancdata, flags, addr = conn.recvmsg(1024, socket.CMSG_LEN(fds.itemsize))
for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds.frombytes(cmsg_data[:len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
target_fd = fds[0]
os.write(target_fd, b"PWNED_VIA_FS_SOCKET\\n")
os.close(target_fd)
conn.close()
s.close()
print("DONE")
""")

    def send_fd():
        import time

        for _ in range(50):
            if sock_path.exists():
                break
            time.sleep(0.05)
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.connect(str(sock_path))
            anc = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [leaked_fd]).tobytes())]
            client.sendmsg([b"FD"], anc)
            client.close()
        except Exception:
            pass

    t = threading.Thread(target=send_fd, daemon=True)
    t.start()

    try:
        prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
        cp = run_confined([sys.executable, str(probe), str(sock_path)], prof)
        assert "PermissionError" in cp.stderr, cp.stderr[-300:]  # design review: kernel refuses to create the socket (no MAKE_SOCK in rw)
    finally:
        os.close(leaked_fd)
        t.join(timeout=2)

    # Invariant: Target must remain unmutated by the confined worker.
    # Repro: This fails because secret.txt was overwritten via SCM_RIGHTS over filesystem socket.
    assert secret.read_text() == "ORIGINAL_SECRET\n", (
        "FINDING 7: Confined worker escaped sandbox via filesystem UNIX domain socket SCM_RIGHTS!"
    )


def test_gate_permits_symlink_pointing_to_git_dir(tmp_path):
    """FINDING 8: Gate Lands Patches Creating Symlinks to Target .git Directory.

    Root Cause: gate.py verifies patch applicability via `git apply --check`,
    but git apply permits creating symlinks whose target is `.git` or `.git/...`.
    When landed, a symbolic link directly into internal git metadata is committed
    to the target repository, corrupting repo isolation.
    """
    repo = _init_git_repo(tmp_path / "repo")

    diff = """diff --git a/git_link b/git_link
new file mode 120000
--- /dev/null
+++ b/git_link
@@ -0,0 +1 @@
+.git
\\ No newline at end of file
"""
    eff = ProposedEffect(diff, "worker", touched_files=("git_link",))
    tree = head_tree(repo)
    ident = target_identity(repo)
    dec = land(
        repo,
        eff,
        ObligationSet((_held(),)),
        expected_tree=tree,
        verified_patch_sha256=eff.patch_sha256,
        expected_identity=ident,
    )

    # Invariant: Gate must refuse patches that create symlinks pointing into .git metadata.
    # Repro: This fails because gate returns LANDED and commits the symlink into the repository.
    assert dec.outcome is GateOutcome.REFUSED, (
        "FINDING 8: gate.land() accepted and committed a symlink pointing directly to .git!"
    )


def test_gate_permits_patch_touching_hlith_metadata(tmp_path):
    """FINDING 9: Gate Lands Patches Modifying .hlith Control Directory.

    Root Cause: gate.py does not inspect touched file paths for reserved
    metadata directories such as `.hlith/`. An untrusted worker can propose
    changes that modify or create `.hlith/config.json` or `.hlith-journal.json`,
    tampering with hlith's supervisor configuration or recovery records.
    """
    repo = _init_git_repo(tmp_path / "repo")

    diff = """diff --git a/.hlith/config.json b/.hlith/config.json
new file mode 100644
--- /dev/null
+++ b/.hlith/config.json
@@ -0,0 +1 @@
+{"backdoor": true}
"""
    eff = ProposedEffect(diff, "worker", touched_files=(".hlith/config.json",))
    tree = head_tree(repo)
    ident = target_identity(repo)
    dec = land(
        repo,
        eff,
        ObligationSet((_held(),)),
        expected_tree=tree,
        verified_patch_sha256=eff.patch_sha256,
        expected_identity=ident,
    )

    # Invariant: Gate must refuse patches that touch .hlith metadata.
    # Repro: This fails because gate returns LANDED and writes to .hlith/config.json.
    assert dec.outcome is GateOutcome.REFUSED, (
        "FINDING 9: gate.land() accepted and committed modifications into .hlith metadata!"
    )


def test_ast_parse_hangs_on_worker_created_fifo(tmp_path):
    """FINDING 10: AST Parser Hangs Indefinitely on Named Pipes (FIFOs).

    Root Cause: differential._parse(path) directly calls path.read_text(...) on
    all files discovered by _iter_py(). Because Python open() on a FIFO blocks
    until a writer process connects, an untrusted FIFO ending in .py stalls
    the differential verifier indefinitely in kernel sleep.
    """
    from hlith.differential import _parse

    fifo = tmp_path / "test_blocked.py"
    os.mkfifo(fifo)

    done = threading.Event()

    def parse_fifo():
        _parse(fifo)
        done.set()

    t = threading.Thread(target=parse_fifo, daemon=True)
    t.start()
    completed = done.wait(timeout=0.5)

    # Invariant: AST parser must not hang on non-regular files (FIFOs).
    # Repro: This fails because completed is False (thread remains blocked in kernel open()).
    assert completed, (
        "FINDING 10: differential._parse() hung indefinitely in open() on a worker-created FIFO!"
    )


def test_gate_permits_symlink_pointing_outside_repository_root(tmp_path):
    """FINDING 11: Gate Lands Patches Creating Symlinks That Escape Repository Root.

    Root Cause: gate.py relies on `git apply --check` for patch validation.
    While git apply prevents ../ in the patch pathspec itself, it does NOT validate
    symlink contents. A patch creating a symlink whose target is `../../../../etc/passwd`
    or `/etc/shadow` is applied and committed into the target repository, creating a link
    that points outside the repository working tree and exposing sensitive host files.
    """
    repo = _init_git_repo(tmp_path / "repo")

    diff = """diff --git a/leak_rel b/leak_rel
new file mode 120000
--- /dev/null
+++ b/leak_rel
@@ -0,0 +1 @@
+../../../../etc/passwd
\\ No newline at end of file
"""
    eff = ProposedEffect(diff, "worker", touched_files=("leak_rel",))
    tree = head_tree(repo)
    ident = target_identity(repo)
    dec = land(
        repo,
        eff,
        ObligationSet((_held(),)),
        expected_tree=tree,
        verified_patch_sha256=eff.patch_sha256,
        expected_identity=ident,
    )

    # Invariant: Gate must refuse patches that create symlinks pointing outside the repository root.
    # Repro: This fails because gate returns LANDED and commits the escaping symlink.
    assert dec.outcome is GateOutcome.REFUSED, (
        "FINDING 11: gate.land() accepted and committed a symlink escaping the repository root!"
    )


def test_stage_git_config_cannot_execute_in_diff_stage(tmp_path):
    """DEFENSE HOLDS: Git config inside stage repo does not execute during diff generation.

    Verifies that malicious git config placed in stage by a worker cannot execute
    commands in the supervisor during `_diff_stage` because GIT_DIR points to
    a bare repository in scratch.
    """
    from hlith.runtime import _diff_stage

    target = _init_git_repo(tmp_path / "target")
    stage = tmp_path / "stage"
    scratch = tmp_path / "scratch"
    stage.mkdir()
    scratch.mkdir()
    (stage / "a.py").write_text("x = 2\n")

    pwn_marker = tmp_path / "stage_config_pwn.txt"
    (stage / ".git").mkdir()
    (stage / ".git" / "config").write_text(f"""
[core]
    fsmonitor = "touch {pwn_marker}"
""")
    diff, touched, ignored, *_ = _diff_stage(target, stage, scratch)
    assert not pwn_marker.exists(), "stage .git config executed during _diff_stage!"
    assert "a.py" in touched


def test_tty_stdin_ioctl_tiocsti_neutralized(tmp_path):
    """DEFENSE HOLDS: TTY stdin IOCTL (TIOCSTI/TIOCLINUX) is neutralized by DEVNULL.

    ATLAS Vector 1: Inherited TTY descriptors permit TIOCSTI command injection.
    Verifies that design review's configuration (stdin=subprocess.DEVNULL) ensures TIOCSTI
    fails with ENOTTY (errno 25), and /dev/tty cannot be opened under Landlock (EACCES).
    """
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()

    probe = stage / "probe.py"
    probe.write_text("""import os, sys, fcntl, termios
# 1. TIOCSTI on stdin (fd 0)
try:
    fcntl.ioctl(0, termios.TIOCSTI, b'x')
    print('TIOCSTI:SUCCESS')
except OSError as e:
    print(f'TIOCSTI:DENIED:{e.errno}')

# 2. Open /dev/tty
try:
    with open('/dev/tty', 'r') as f:
        print('OPEN_TTY:SUCCESS')
except OSError as e:
    print(f'OPEN_TTY:DENIED:{e.errno}')
""")
    prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
    cp = run_confined([sys.executable, str(probe)], prof)
    assert cp.returncode == 0, cp.stderr
    assert "TIOCSTI:DENIED:25" in cp.stdout  # ENOTTY
    assert "OPEN_TTY:DENIED:13" in cp.stdout or "OPEN_TTY:DENIED:2" in cp.stdout  # EACCES, or ENOENT: /dev/tty is absent from the worker root


def test_proc_supervisor_cmdline_disclosure(tmp_path):
    """FINDING 12: Information Disclosure via Unshared PID Namespace and Host /proc.

    ATLAS Vector 2: Filesystem policy does not cover /proc/<pid>/* and nsfs routes.
    Because CLONE_NEWPID is not unshared and /proc is not remounted as a private procfs,
    the confined worker can inspect the host's /proc hierarchy. It can read
    /proc/<parent_pid>/cmdline to discover supervisor arguments, private repository
    paths, and script sources, and enumerate open descriptor numbers in /proc/<parent_pid>/fd.
    """
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()

    parent_pid = os.getpid()
    probe = stage / "probe.py"
    probe.write_text(f"""import os
with open('/proc/{parent_pid}/cmdline', 'r') as f:
    cmd = f.read()
print('DISCLOSED_CMDLINE_LEN:', len(cmd))
fds = os.listdir('/proc/{parent_pid}/fd')
print('DISCLOSED_FD_COUNT:', len(fds))
""")
    prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
    cp = run_confined([sys.executable, str(probe)], prof)

    # Invariant: the worker must not see the supervisor's process at all. It lives in its own pid
    # namespace with a fresh /proc, so the host pid is absent (FileNotFoundError), not merely unreadable.
    assert "DISCLOSED_CMDLINE_LEN" not in cp.stdout and "FileNotFoundError" in cp.stderr, (
        f"FINDING 12: Confined worker disclosed supervisor cmdline via host /proc: {cp.stdout.strip()} {cp.stderr[-200:]}"
    )


def test_stat_metadata_disclosure_outside_sandbox(tmp_path):
    """FINDING 13: Stat and Topology Disclosure on Unallowed Host Paths.

    ATLAS Vector 3: Landlock does not restrict stat(), lstat(), or access().
    Metadata disclosure and filesystem topology enumeration are outside a Landlock
    filesystem policy. A confined worker can call os.stat() on sensitive host paths
    outside the allowed set (e.g. /etc/shadow, /root, ~/.ssh), disclosing file existence,
    permissions, exact size, and modification timestamps.
    """
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()

    probe = stage / "probe.py"
    probe.write_text("""import os
disclosed = []
for p in ['/etc/passwd', '/etc/shadow', '/root', os.path.expanduser('~/.bashrc')]:
    try:
        st = os.stat(p)
        disclosed.append(f"{p}:{st.st_size}:{oct(st.st_mode)}")
    except OSError:
        pass
print('DISCLOSED:' + ';'.join(disclosed))
""")
    prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
    cp = run_confined([sys.executable, str(probe)], prof)
    assert cp.returncode == 0, cp.stderr

    # Invariant: Confined worker must not be able to stat host paths outside the profile.
    # Repro: Fails because Landlock ABI 8 does not restrict stat(), disclosing sensitive metadata.
    assert cp.stdout.strip() == "DISCLOSED:", (
        f"FINDING 13: Confined worker disclosed metadata of unallowed host paths: {cp.stdout.strip()}"
    )


def test_gate_proposer_id_crlf_injection_forges_landing_key(tmp_path):
    """FINDING 14: Commit Header CRLF Injection in proposer_id Forges Landing Key.

    Root Cause: gate.land() records `Hlith-Key: {key}` in commit messages and
    implements idempotency via `if f"Hlith-Key: {key}" in last:`. However,
    gate.land() embeds `effect.proposer_id` directly into the commit message
    without sanitizing newlines (\\r / \\n). An attacker can inject a future
    or arbitrary `Hlith-Key: <key>` header into a prior commit. When the target
    patch is subsequently submitted, gate.land() falsely assumes it already landed
    and returns LANDED without applying the patch, silently suppressing changes.
    """
    from hlith.gate import landing_key

    repo = _init_git_repo(tmp_path / "repo")

    # Target patch that will be suppressed
    future_diff = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-x = 1
+x = 999
"""
    future_eff = ProposedEffect(future_diff, "future_worker")
    future_tree = head_tree(repo)
    future_obs = ObligationSet((_held("target_task"),))
    future_key = landing_key(future_tree, future_eff, future_obs)

    # Malicious prior commit injecting future_key into git commit log via proposer_id
    diff1 = """diff --git a/a.py b/a.py
--- a/a.py
+++ b/a.py
@@ -1 +1 @@
-x = 1
+x = 2
"""
    evil_proposer = f"attacker\\n\\nHlith-Key: {future_key}"
    eff1 = ProposedEffect(diff1, evil_proposer)
    tree1 = head_tree(repo)
    ident = target_identity(repo)
    dec1 = land(
        repo,
        eff1,
        ObligationSet((_held("prior_task"),)),
        expected_tree=tree1,
        verified_patch_sha256=eff1.patch_sha256,
        expected_identity=ident,
    )
    assert dec1.outcome is GateOutcome.LANDED

    # Invariant: Gate must not allow a forged commit header to suppress a real patch.
    # Repro: This fails because gate returns LANDED, but the target patch was never applied.
    dec2 = land(
        repo,
        future_eff,
        future_obs,
        expected_tree=future_tree,
        verified_patch_sha256=future_eff.patch_sha256,
        expected_identity=ident,
    )
    # design review: the future patch was verified against a base tree the first landing already changed, so a
    # correct gate REFUSES it (exit 4). The finding's real invariant: never LANDED-without-applying,
    # and the proposer cannot plant a trailer in the commit log.
    assert dec2.outcome is GateOutcome.REFUSED and "base-tree-changed" in dec2.blocking, (
        "FINDING 14: proposer_id CRLF injection forged landing key and silently suppressed patch!"
    )
    trailers = subprocess.run(
        ["git", "-C", str(repo), "log", "--format=%(trailers:key=Hlith-Key,valueonly,separator=%x2C)"],
        capture_output=True, text=True).stdout
    assert future_key not in trailers  # the forged key is inert text on the proposer line, not a trailer


def test_gate_permits_c_quoted_patch_touching_hlith_metadata(tmp_path):
    r"""FINDING 15: C-Quoted Diff Headers Bypass patch_violations() Reserved Path Checks.

    Root Cause: gate.patch_violations() regexes `^(?:---|\+\+\+) (?:a|b)/(.+)$` and
    `^a/(.+?) b/(.+)$` fail to match paths enclosed in C-style double quotes (which
    git outputs whenever paths contain spaces, tabs, quotes, or non-ASCII characters).
    As a result, `paths` is empty, patch_violations() returns no violations, and
    gate.land() applies and commits modifications to reserved paths like .hlith/config.json.
    """
    repo = _init_git_repo(tmp_path / "repo")

    # Patch with C-quoted paths touching .hlith/config.json
    diff = '''diff --git "a/.hlith/config.json" "b/.hlith/config.json"
new file mode 100644
--- /dev/null
+++ "b/.hlith/config.json"
@@ -0,0 +1 @@
+{"backdoor": true}
'''
    eff = ProposedEffect(diff, "worker", touched_files=(".hlith/config.json",))
    tree = head_tree(repo)
    ident = target_identity(repo)
    dec = land(
        repo,
        eff,
        ObligationSet((_held(),)),
        expected_tree=tree,
        verified_patch_sha256=eff.patch_sha256,
        expected_identity=ident,
    )

    # Invariant: Gate must reject patches modifying reserved .hlith directory even when C-quoted.
    # Repro: This fails because gate returns LANDED and creates .hlith/config.json.
    assert dec.outcome is GateOutcome.REFUSED, (
        "FINDING 15: C-quoted diff header bypassed patch_violations() and mutated .hlith metadata!"
    )


def test_gate_permits_circular_symlinks(tmp_path):
    """FINDING 16: Gate Lands Circular Symlink Loops (ELOOP DoS).

    Root Cause: gate.patch_violations() verifies that individual symlink targets do
    not leave the repository, but does not check for circular reference topologies.
    A patch adding `link_a -> link_b` and `link_b -> link_a` is accepted and landed,
    corrupting the repository and causing ELOOP errors in downstream tools.
    """
    repo = _init_git_repo(tmp_path / "repo")

    diff = """diff --git a/link_a b/link_a
new file mode 120000
--- /dev/null
+++ b/link_a
@@ -0,0 +1 @@
+link_b
\\ No newline at end of file
diff --git a/link_b b/link_b
new file mode 120000
--- /dev/null
+++ b/link_b
@@ -0,0 +1 @@
+link_a
\\ No newline at end of file
"""
    eff = ProposedEffect(diff, "worker", touched_files=("link_a", "link_b"))
    tree = head_tree(repo)
    ident = target_identity(repo)
    dec = land(
        repo,
        eff,
        ObligationSet((_held(),)),
        expected_tree=tree,
        verified_patch_sha256=eff.patch_sha256,
        expected_identity=ident,
    )

    # Invariant: Gate must refuse patches creating circular symlink loops.
    # Repro: This fails because gate returns LANDED and commits the loop.
    assert dec.outcome is GateOutcome.REFUSED, (
        "FINDING 16: gate.land() accepted and committed circular symlink loop into repository!"
    )


def test_supervisor_crash_on_non_utf8_diff_content(tmp_path):
    """FINDING 17: Supervisor Crashes with UnicodeDecodeError on Non-UTF-8 Stage Files.

    Root Cause: runtime._git() invokes subprocess.run(cmd, capture_output=True, text=True).
    When a worker creates or modifies a file containing non-UTF-8 byte sequences
    without NUL bytes (e.g. Latin-1 text such as \\x80\\x81\\x82\\n), git diff treats the file
    as text and emits raw patch bytes. Subprocess text decoding with strict UTF-8
    crashes the supervisor with an unhandled UnicodeDecodeError before any boundary
    or gate decision can be reached.
    """
    target = _init_git_repo(tmp_path / "target")

    worker_code = (
        "import os\n"
        "open('latin1.txt', 'wb').write(b'hello ' + bytes([0x80, 0x81, 0x82]) + b' world\\n')\n"
    )
    worker = [sys.executable, "-c", worker_code]

    # Invariant: run_worker() must not crash the supervisor with UnicodeDecodeError.
    # Repro: This fails because _diff_stage calls _git(..., text=True), raising UnicodeDecodeError.
    try:
        run = run_worker(target, worker)
        assert run is not None
    except UnicodeDecodeError as e:
        pytest.fail(f"FINDING 17: Supervisor crashed with UnicodeDecodeError in _diff_stage: {e}")


def test_supervisor_crash_on_deep_directory_hierarchy_exceeding_path_max(tmp_path):
    """FINDING 18: Supervisor Crashes with OSError (File name too long) on Deep Directories.

    Root Cause: runtime._scan_stage() uses os.walk(stage) and calls os.lstat(Path(dirpath, name)).
    If a worker constructs a directory hierarchy whose total path exceeds Linux PATH_MAX
    (4096 bytes) using relative chdir/mkdir, os.lstat() raises OSError: [Errno 36] File name too long.
    This unhandled OSError crashes the supervisor process during stage scanning.
    """
    target = _init_git_repo(tmp_path / "target")

    worker_code = (
        "import os\n"
        "cur = 'a' * 200\n"
        "for _ in range(25):\n"
        "    os.mkdir(cur)\n"
        "    os.chdir(cur)\n"
        "open('deep.txt', 'w').write('deep')\n"
    )
    worker = [sys.executable, "-c", worker_code]

    # Invariant: run_worker() must handle or reject deep directories without crashing supervisor.
    # Repro: This fails because _scan_stage crashes on os.lstat() with [Errno 36] File name too long.
    try:
        run = run_worker(target, worker)
        assert run is not None
    except EffectRejected:
        pass  # design review: a stage deeper than the cap cannot apply to the target; rejecting it IS the handling
    except OSError as e:
        if e.errno == 36:  # ENAMETOOLONG
            pytest.fail(f"FINDING 18: Supervisor crashed with OSError (File name too long) in _scan_stage: {e}")
        raise


def test_gate_permits_symlink_cycle_through_existing_repo_symlink(tmp_path):
    r"""FINDING 19: Gate Permits Symlink Cycles Closing Through Existing Repo Symlinks.

    Root Cause: gate.patch_violations() only analyzes symlink topology within the
    incoming patch itself (the `links` map populated from the diff). If the repository
    already contains a symlink `link_a -> link_b`, and the patch introduces `link_b -> link_a`
    (or any multi-hop cycle closing through pre-existing symlinks in the target tree),
    the cycle goes undetected by the regex check. gate.land() returns GateOutcome.LANDED,
    committing the circular symlink and causing ELOOP (Too many levels of symbolic links)
    for all repository consumers.
    """
    repo = _init_git_repo(tmp_path / "repo")
    os.symlink("link_b", str(repo / "link_a"))
    subprocess.run(["git", "-C", str(repo), "add", "link_a"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "add link_a"],
        check=True,
        capture_output=True,
    )

    diff = """diff --git a/link_b b/link_b
new file mode 120000
index 0000000..1234567
--- /dev/null
+++ b/link_b
@@ -0,0 +1 @@
+link_a
\\ No newline at end of file
"""
    eff = ProposedEffect(diff, "worker", touched_files=("link_b",))
    tree = head_tree(repo)
    ident = target_identity(repo)
    dec = land(
        repo,
        eff,
        ObligationSet((_held(),)),
        expected_tree=tree,
        verified_patch_sha256=eff.patch_sha256,
        expected_identity=ident,
    )

    # Invariant: The gate must refuse patches that create circular symlink loops,
    # including cycles that complete through existing symlinks in the repository.
    # Repro: This fails because patch_violations only checks intra-patch cycles,
    # returning GateOutcome.LANDED and committing an ELOOP corrupting the tree.
    assert dec.outcome is GateOutcome.REFUSED and any("symlink-cycle" in b for b in dec.blocking), (
        f"FINDING 19: gate.land() accepted circular symlink closing through existing repo symlink: {dec.outcome} {dec.blocking}"
    )


def test_worker_environment_scrubbed_of_credentials(tmp_path, monkeypatch):
    """DEFENSE HOLDS: Worker environment does not inherit host credentials or secrets."""
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_supersecret123456789")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws_supersecret_access_key")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/ssh-agent.sock")

    probe = stage / "probe.py"
    probe.write_text("""import os, json
leaked = [k for k in ["GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK"] if k in os.environ]
print(json.dumps(leaked))
""")
    prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
    cp = run_confined([sys.executable, str(probe)], prof, cwd=str(stage))
    assert cp.returncode == 0, cp.stderr
    assert cp.stdout.strip() == "[]"


def test_attack_on_pid1_reaping_child_cannot_signal_or_kill_driver_pid1(tmp_path):
    """DEFENSE HOLDS: In Layer 1 cmd mode, confined child cannot signal or kill driver PID 1 to disrupt namespace cleanup."""
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"], check=True)

    code = """
import os, signal, json
res = {}
for sig_name, sig_val in [("SIGKILL", signal.SIGKILL), ("SIGTERM", signal.SIGTERM), ("SIGINT", signal.SIGINT)]:
    try:
        os.kill(1, sig_val)
        res[sig_name] = "SENT"
    except Exception as e:
        res[sig_name] = f"denied:{type(e).__name__}"

open('calc.py', 'a').write('# ' + json.dumps(res) + '\\n')
"""
    from hlith.runtime import run_worker
    run = run_worker(r, [sys.executable, "-c", code], layer1=True)
    try:
        assert "denied:PermissionError" in run.effect.unified_diff, run.effect.unified_diff
        assert "SENT" not in run.effect.unified_diff
    finally:
        run.graph.close()


def test_finding_24_residual_closed_pathname_socket_in_granted_path_is_rejected_before_the_worker_starts(tmp_path):
    """FINDING 24 RESIDUAL (CLOSED at the sandbox layer by review df45d27): a pathname AF_UNIX socket inside a granted path was
    reachable under net=False. run_confined now vets every grant and raises GrantError before anything starts.
    Original root cause (kept for the record):

    Root Cause: Linux network namespaces (CLONE_NEWNET) scope network interfaces and abstract UNIX domain sockets
    (\0...), but do NOT scope filesystem pathname UNIX domain sockets. Pathname socket lookups are mediated solely
    by the mount namespace and filesystem permissions. Furthermore, Landlock ABI (up to ABI 8) provides no
    mediation for connecting to pre-existing S_IFSOCK filesystem nodes (only MAKE_SOCK creation is scoped).
    Consequently, if a granted directory (such as a cloned target repository or ro_bind path) contains a UNIX
    domain socket connected to a host-side listener, a confined worker under Profile(net=False) can still
    connect, send/receive data, and pass file descriptors.
    Outside granted paths (e.g. host temporary directories): inaccessible via ENOENT / private tmpfs root.
    """
    target = tmp_path / "target"
    stage = tmp_path / "stage"
    target.mkdir()
    stage.mkdir()

    sock_path = str(target / "host.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)

    probe = stage / "probe.py"
    probe.write_text(f"""
import socket, json
res = {{}}
# Pathname socket inside granted path
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect({repr(sock_path)})
    s.sendall(b"RESIDUAL-REACHABLE")
    res["granted_path_sock"] = "CONNECTED"
    s.close()
except Exception as e:
    res["granted_path_sock"] = f"denied:{{type(e).__name__}}"

print(json.dumps(res))
""")

    received = []
    def serve():
        try:
            conn, _ = srv.accept()
            data = conn.recv(100)
            received.append(data)
            conn.close()
        except Exception:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    try:
        prof = Profile(ro=(str(target),), rw=(str(stage),), ro_bind=(str(target),), net=False)
        from hlith.sandbox import GrantError
        with pytest.raises(GrantError, match="special file"):
            run_confined([sys.executable, "-I", str(probe)], prof)
        t.join(timeout=0.3)
        assert received == [], f"the worker must never have started, host got: {received}"
    finally:
        srv.close()
        t.join(timeout=1)


# ============================================================================
# FINDING 23: Broad Network Surface Attacks Under net=False Confinement
# ============================================================================


def test_finding_23_udp_ipv4_and_ipv6_exfiltration_denied_and_listeners_unreached(tmp_path):
    """FINDING 23.1: UDP IPv4 and IPv6 datagram exfiltration denied by unshared network namespace."""
    l4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    l4.bind(("127.0.0.1", 0))
    l4.settimeout(0.5)
    port4 = l4.getsockname()[1]

    l6 = None
    port6 = 0
    try:
        l6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        l6.bind(("::1", 0))
        l6.settimeout(0.5)
        port6 = l6.getsockname()[1]
    except OSError:
        pass

    probe = tmp_path / "probe.py"
    probe.write_text(f"""
import socket, json
res = {{}}
# IPv4
try:
    s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s4.sendto(b"HLITH-EXFIL-UDP4", ("127.0.0.1", {port4}))
    res["udp4"] = "SENT"
except OSError as e:
    res["udp4"] = f"denied:{{e.errno}}"

# IPv6
if {port6} > 0:
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s6.sendto(b"HLITH-EXFIL-UDP6", ("::1", {port6}))
        res["udp6"] = "SENT"
    except OSError as e:
        res["udp6"] = f"denied:{{e.errno}}"

# External IP
try:
    s_ext = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_ext.sendto(b"HLITH-EXFIL-EXT", ("8.8.8.8", 53))
    res["udp_ext"] = "SENT"
except OSError as e:
    res["udp_ext"] = f"denied:{{e.errno}}"

print(json.dumps(res))
""")

    prof = Profile(rw=(str(tmp_path),), net=False)
    try:
        cp = run_confined([sys.executable, "-I", str(probe)], prof)
        assert cp.returncode == 0, cp.stderr
        out = json.loads(cp.stdout.strip())
        assert out["udp4"].startswith("denied:"), f"UDP4 unexpectedly allowed: {out}"
        if port6 > 0:
            assert out["udp6"].startswith("denied:"), f"UDP6 unexpectedly allowed: {out}"
        assert out["udp_ext"].startswith("denied:"), f"UDP external unexpectedly allowed: {out}"

        # Host listeners must receive 0 datagrams
        try:
            data, _ = l4.recvfrom(100)
        except (TimeoutError, socket.timeout):
            data = None
        assert data is None, f"Host UDP4 listener received exfiltration datagram: {data}"

        if l6 is not None:
            try:
                data6, _ = l6.recvfrom(100)
            except (TimeoutError, socket.timeout):
                data6 = None
            assert data6 is None, f"Host UDP6 listener received exfiltration datagram: {data6}"
    finally:
        l4.close()
        if l6 is not None:
            l6.close()


def test_finding_23_abstract_unix_sockets_isolated_by_netns_and_landlock(tmp_path):
    """FINDING 23.2: Abstract UNIX domain sockets (datagram & stream) isolated by network namespace and Landlock scoping."""
    abs_dgram_name = f"\0hlith_test_abs_dgram_{os.getpid()}"
    abs_stream_name = f"\0hlith_test_abs_stream_{os.getpid()}"

    dgram_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    dgram_sock.bind(abs_dgram_name)
    dgram_sock.settimeout(0.5)

    stream_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream_sock.bind(abs_stream_name)
    stream_sock.listen(1)
    stream_sock.settimeout(0.5)

    probe = tmp_path / "probe.py"
    probe.write_text(f"""
import socket, json
res = {{}}
# Abstract dgram
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.sendto(b"HLITH-ABS-DGRAM", {repr(abs_dgram_name)})
    res["abs_dgram"] = "SENT"
except Exception as e:
    res["abs_dgram"] = f"denied:{{type(e).__name__}}:{{e}}"

# Abstract stream
try:
    s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s2.settimeout(0.5)
    s2.connect({repr(abs_stream_name)})
    res["abs_stream"] = "CONNECTED"
except Exception as e:
    res["abs_stream"] = f"denied:{{type(e).__name__}}:{{e}}"

print(json.dumps(res))
""")

    prof = Profile(rw=(str(tmp_path),), net=False)
    try:
        cp = run_confined([sys.executable, "-I", str(probe)], prof)
        assert cp.returncode == 0, cp.stderr
        out = json.loads(cp.stdout.strip())
        assert out["abs_dgram"].startswith("denied:"), f"Abstract dgram unexpectedly allowed: {out}"
        assert out["abs_stream"].startswith("denied:"), f"Abstract stream unexpectedly allowed: {out}"

        try:
            data, _ = dgram_sock.recvfrom(100)
        except (TimeoutError, socket.timeout):
            data = None
        assert data is None, f"Host abstract dgram listener received data: {data}"
    finally:
        dgram_sock.close()
        stream_sock.close()


def test_finding_23_raw_and_af_packet_sockets_denied(tmp_path):
    """FINDING 23.3: AF_PACKET and raw sockets denied with PermissionError inside unprivileged container."""
    probe = tmp_path / "probe.py"
    probe.write_text("""
import socket, json
res = {}
for name, args in [
    ("af_packet_raw", (socket.AF_PACKET, socket.SOCK_RAW, 0)),
    ("af_packet_dgram", (socket.AF_PACKET, socket.SOCK_DGRAM, 0)),
    ("raw_icmp", (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)),
    ("raw_ip", (socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)),
]:
    try:
        s = socket.socket(*args)
        res[name] = "OPEN"
        s.close()
    except Exception as e:
        res[name] = f"denied:{type(e).__name__}:{e}"

print(json.dumps(res))
""")

    prof = Profile(rw=(str(tmp_path),), net=False)
    cp = run_confined([sys.executable, "-I", str(probe)], prof)
    assert cp.returncode == 0, cp.stderr
    out = json.loads(cp.stdout.strip())
    for k in ("af_packet_raw", "af_packet_dgram", "raw_icmp", "raw_ip"):
        assert "PermissionError" in out[k] or "denied:" in out[k], (k, out)


def test_finding_23_host_loopback_tcp_services_unreachable(tmp_path):
    """FINDING 23.4: TCP loopback connections to host services blocked by Landlock and netns isolation."""
    s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s4.bind(("127.0.0.1", 0))
    s4.listen(1)
    s4.settimeout(0.5)
    port4 = s4.getsockname()[1]

    s6 = None
    port6 = 0
    try:
        s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s6.bind(("::1", 0))
        s6.listen(1)
        s6.settimeout(0.5)
        port6 = s6.getsockname()[1]
    except OSError:
        pass

    probe = tmp_path / "probe.py"
    probe.write_text(f"""
import socket, json
res = {{}}
# TCP4
try:
    c4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c4.settimeout(0.5)
    c4.connect(("127.0.0.1", {port4}))
    res["tcp4"] = "CONNECTED"
except Exception as e:
    res["tcp4"] = f"denied:{{type(e).__name__}}:{{e}}"

# TCP6
if {port6} > 0:
    try:
        c6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        c6.settimeout(0.5)
        c6.connect(("::1", {port6}))
        res["tcp6"] = "CONNECTED"
    except Exception as e:
        res["tcp6"] = f"denied:{{type(e).__name__}}:{{e}}"

print(json.dumps(res))
""")

    prof = Profile(rw=(str(tmp_path),), net=False)
    try:
        cp = run_confined([sys.executable, "-I", str(probe)], prof)
        assert cp.returncode == 0, cp.stderr
        out = json.loads(cp.stdout.strip())
        assert out["tcp4"].startswith("denied:"), f"TCP4 unexpectedly connected: {out}"
        if port6 > 0:
            assert out["tcp6"].startswith("denied:"), f"TCP6 unexpectedly connected: {out}"
    finally:
        s4.close()
        if s6 is not None:
            s6.close()


def test_finding_23_netlink_and_interface_enumeration_isolated(tmp_path):
    """FINDING 23.5: Netlink and socket.if_nameindex() see only isolated netns (lo at most, zero host interfaces)."""
    probe = tmp_path / "probe.py"
    probe.write_text("""
import socket, struct, json

# 1. if_nameindex
try:
    ifnames = [name for _, name in socket.if_nameindex()]
except Exception as e:
    ifnames = f"err:{e}"

# 2. Netlink RTM_GETLINK dump
RTM_GETLINK = 18
NLM_F_REQUEST = 1
NLM_F_DUMP = 0x300
nlmsghdr = struct.pack("=IHHII", 16 + 16, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 1, 0)
ifinfomsg = struct.pack("=BxHiII", socket.AF_UNSPEC, 0, 0, 0, 0)

nl_names = []
try:
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    s.bind((0, 0))
    s.send(nlmsghdr + ifinfomsg)
    data = s.recv(4096)
    s.close()
    if len(data) >= 32:
        payload = data[16:struct.unpack("=I", data[:4])[0]]
        attrs = payload[16:]
        offset = 0
        while offset + 4 <= len(attrs):
            rta_len, rta_type = struct.unpack("=HH", attrs[offset:offset+4])
            if rta_len < 4 or offset + rta_len > len(attrs): break
            if rta_type == 3: # IFLA_IFNAME
                name = attrs[offset+4:offset+rta_len].rstrip(b"\\0").decode()
                nl_names.append(name)
            offset += (rta_len + 3) & ~3
except Exception as e:
    nl_names = f"err:{e}"

print(json.dumps({"if_nameindex": ifnames, "netlink_names": nl_names}))
""")

    prof = Profile(rw=(str(tmp_path),), net=False)
    cp = run_confined([sys.executable, "-I", str(probe)], prof)
    assert cp.returncode == 0, cp.stderr
    out = json.loads(cp.stdout.strip())
    # The confined process may only see 'lo' or an empty list; zero host interfaces
    assert set(out["if_nameindex"]) <= {"lo"}, f"Host interface leaked: {out}"
    if isinstance(out["netlink_names"], list):
        assert set(out["netlink_names"]) <= {"lo"}, f"Host interface leaked via netlink: {out}"


def test_finding_23_proc_net_information_disclosure_blocked(tmp_path):
    """FINDING 23.6: /proc/net/* tables contain zero host socket connections, routes, or ARP entries."""
    probe = tmp_path / "probe.py"
    probe.write_text("""
import os, json

def non_header_lines(path):
    if not os.path.exists(path):
        return []
    lines = [l.strip() for l in open(path).readlines() if l.strip()]
    # Skip headers
    if path in ("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6", "/proc/net/unix"):
        return lines[1:]
    elif path == "/proc/net/dev":
        return [l for l in lines[2:] if not l.startswith("lo:")]
    elif path == "/proc/net/arp":
        return lines[1:]
    elif path == "/proc/net/route":
        return lines[1:]
    return lines

res = {
    "tcp": non_header_lines("/proc/net/tcp"),
    "udp": non_header_lines("/proc/net/udp"),
    "dev_non_lo": non_header_lines("/proc/net/dev"),
    "arp": non_header_lines("/proc/net/arp"),
    "route": non_header_lines("/proc/net/route"),
    "unix": non_header_lines("/proc/net/unix"),
}
print(json.dumps(res))
""")

    prof = Profile(rw=(str(tmp_path),), net=False)
    cp = run_confined([sys.executable, "-I", str(probe)], prof)
    assert cp.returncode == 0, cp.stderr
    out = json.loads(cp.stdout.strip())
    # All entries must be empty: zero host connections or devices leaked
    assert len(out["tcp"]) == 0, f"Host TCP sockets leaked in /proc/net/tcp: {out['tcp']}"
    assert len(out["udp"]) == 0, f"Host UDP sockets leaked in /proc/net/udp: {out['udp']}"
    assert len(out["dev_non_lo"]) == 0, f"Host devices leaked in /proc/net/dev: {out['dev_non_lo']}"
    assert len(out["arp"]) == 0, f"Host ARP cache leaked in /proc/net/arp: {out['arp']}"
    assert len(out["route"]) == 0, f"Host route table leaked in /proc/net/route: {out['route']}"
    assert len(out["unix"]) == 0, f"Host unix sockets leaked in /proc/net/unix: {out['unix']}"


def test_finding_23_dns_and_system_sockets_unreachable(tmp_path):
    """FINDING 23.7: Host system sockets (/var/run/nscd/socket, dbus, systemd) are unreachable."""
    probe = tmp_path / "probe.py"
    probe.write_text("""
import socket, json
res = {}
targets = [
    "/var/run/nscd/socket",
    "/run/nscd/socket",
    "/run/systemd/private",
    "/run/dbus/system_bus_socket",
]
for p in targets:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(p)
        res[p] = "CONNECTED"
        s.close()
    except Exception as e:
        res[p] = f"denied:{type(e).__name__}:{e}"

print(json.dumps(res))
""")

    prof = Profile(rw=(str(tmp_path),), net=False)
    cp = run_confined([sys.executable, "-I", str(probe)], prof)
    assert cp.returncode == 0, cp.stderr
    out = json.loads(cp.stdout.strip())
    for p, status in out.items():
        assert "CONNECTED" not in status, f"Connected to host system socket {p}: {status}"
        assert "FileNotFoundError" in status or "denied:" in status


def test_finding_23_io_uring_network_operations_confined(tmp_path):
    """FINDING 23.8: io_uring setup succeeds but network socket operations remain strictly bound to empty netns."""
    probe = tmp_path / "probe.py"
    probe.write_text("""
import ctypes, socket, os, json

libc = ctypes.CDLL(None, use_errno=True)
SYS_io_uring_setup = 425

class io_uring_params(ctypes.Structure):
    _fields_ = [
        ("sq_entries", ctypes.c_uint32), ("cq_entries", ctypes.c_uint32),
        ("flags", ctypes.c_uint32), ("sq_thread_cpu", ctypes.c_uint32),
        ("sq_thread_idle", ctypes.c_uint32), ("features", ctypes.c_uint32),
        ("wq_fd", ctypes.c_uint32), ("resv", ctypes.c_uint32 * 3),
        ("sq_off", ctypes.c_uint8 * 40), ("cq_off", ctypes.c_uint8 * 48),
    ]

p = io_uring_params()
ring_fd = libc.syscall(SYS_io_uring_setup, 4, ctypes.byref(p))

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"URING-EXFIL", ("127.0.0.1", 9999))
    send_res = "SENT"
except OSError as e:
    send_res = f"denied:{e.errno}"

print(json.dumps({"ring_fd": ring_fd, "send_res": send_res}))
""")

    prof = Profile(rw=(str(tmp_path),), net=False)
    cp = run_confined([sys.executable, "-I", str(probe)], prof)
    assert cp.returncode == 0, cp.stderr
    out = json.loads(cp.stdout.strip())
    assert out["ring_fd"] >= 0
    assert out["send_res"].startswith("denied:"), f"Socket transmission unexpectedly allowed under io_uring: {out}"


def test_finding_23_layer1_cmd_mode_child_network_surface_confined(tmp_path):
    """FINDING 23.9: Under Layer 1 cmd mode, child process inherits empty netns and cannot reach host UDP listeners."""
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"], check=True)

    l4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    l4.bind(("127.0.0.1", 0))
    l4.settimeout(0.5)
    port4 = l4.getsockname()[1]

    code = f"""
import socket, json
res = {{}}
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"HLITH-CMD-EXFIL", ("127.0.0.1", {port4}))
    res["udp"] = "SENT"
except OSError as e:
    res["udp"] = f"denied:{{e.errno}}"

try:
    s2 = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s2.sendto(b"HLITH-CMD-EXFIL", "\\0hlith_host_abs")
    res["abs"] = "SENT"
except Exception as e:
    res["abs"] = f"denied:{{type(e).__name__}}"

open('calc.py', 'a').write('# ' + json.dumps(res) + '\\n')
"""
    from hlith.runtime import run_worker
    try:
        run = run_worker(r, [sys.executable, "-c", code], layer1=True)
        try:
            assert "denied:101" in run.effect.unified_diff or "denied:" in run.effect.unified_diff
            assert "SENT" not in run.effect.unified_diff
            # Check host listener received nothing
            try:
                data, _ = l4.recvfrom(100)
            except (TimeoutError, socket.timeout):
                data = None
            assert data is None, f"Host listener received child datagram: {data}"

            # Verify artifact declarations
            j = run.graph.to_json()
            assert "socket_events_scope" in j
        finally:
            run.graph.close()
    finally:
        l4.close()


@pytest.mark.real
def test_layer1_double_resume_idempotent_and_rejects_reexecution(tmp_path):
    """DEFENSE HOLDS (real tier: 3 langgraph subprocesses, ~9s): LangGraph state machine
    ignores subsequent resume invocations once at END."""
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"], check=True)

    code = "open('calc.py', 'a').write('# e\\n')\n"
    from hlith.runtime import run_worker
    from hlith.layer1 import resume
    run = run_worker(r, [sys.executable, "-c", code], layer1=True)
    try:
        dec1 = {"outcome": "refused", "exit_status": 10, "blocking": ["fake"]}
        dec2 = {"outcome": "landed", "exit_status": 0, "blocking": []}
        resume(run.graph, dec1)
        assert run.graph.feedback_executions == 1

        # Second resume with conflicting decision
        resume(run.graph, dec2)
        assert run.graph.feedback_executions == 1
    finally:
        run.graph.close()









def test_finding_24_escalation_af_unix_scm_rights_stage_fd_mutation(tmp_path):
    """FINDING 24 ESCALATION (OWNER: review): Pathname AF_UNIX socket in target repository path
    allows untrusted worker to exfiltrate an open writable stage FD via SCM_RIGHTS, enabling
    an external host process to mutate stage files after run_worker completes."""
    import array
    import threading
    import time

    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"], check=True)

    sockpath = r / "receiver.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(sockpath))
    listener.listen(1)
    listener.settimeout(5)

    received = threading.Event()
    release = threading.Event()
    holder = {}

    def recv():
        fd = None
        conn = None
        try:
            conn, _ = listener.accept()
            msg, anc, *rest = conn.recvmsg(100, socket.CMSG_SPACE(4 * 4))
            for level, typ, payload in anc:
                if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
                    fds = array.array("i")
                    fds.frombytes(payload[: len(payload) // fds.itemsize * fds.itemsize])
                    if fds:
                        fd = fds[0]
                        break
            holder["fd"] = fd
            received.set()
            if fd is not None and release.wait(5):
                os.write(fd, b"ESCAPED\n")
                holder["wrote"] = True
        except Exception as e:
            holder["err"] = e
            received.set()
        finally:
            if fd is not None:
                os.close(fd)
            if conn is not None:
                conn.close()

    th = threading.Thread(target=recv, daemon=True)
    th.start()

    code = r"""
import os, socket, array
fd = os.open('escaped.bin', os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
os.write(fd, b'OPEN\n')
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(os.path.join(os.environ["HLITH_TARGET"], "receiver.sock"))
    fds = array.array("i", [fd])
    s.sendmsg([b'PASS'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds)])
    s.close()
except Exception as e:
    pass
os.close(fd)
open('calc.py', 'a').write('# update\n')
"""
    from hlith.runtime import run_worker
    run = None
    try:
        run = run_worker(r, [sys.executable, "-c", code], layer1=True, timeout=15)
        stage = run.graph._session.stage
        at_barrier = (stage / "escaped.bin").read_bytes() if (stage / "escaped.bin").exists() else None
        received.wait(1.0)
        release.set()
        th.join(timeout=2)
        time.sleep(0.1)
        after_barrier = (stage / "escaped.bin").read_bytes() if (stage / "escaped.bin").exists() else None

        assert holder.get("fd") is None, (
            f"FINDING 24 ESCALATION: host receiver obtained stage FD ({holder.get('fd')}); "
            f"before={at_barrier} after={after_barrier}"
        )
        assert after_barrier == at_barrier, (
            f"FINDING 24 ESCALATION: stage file mutated post-worker! before={at_barrier} after={after_barrier}"
        )
    finally:
        release.set()
        listener.close()
        th.join(timeout=1)
        if run is not None and run.graph is not None:
            run.graph.close()
        try:
            sockpath.unlink()
        except FileNotFoundError:
            pass


def test_containment_invariant_concurrent_fork_and_barrier_race(tmp_path):
    """CONTAINMENT INVARIANT: After run_worker exits and before/after measurement,
    no child, grandchild, or descriptor from the worker can mutate the stage.
    Tests setsid double-fork, held descriptors, and rapid racing forks with a 1.0s settle."""
    import time
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"], check=True)

    code = r"""
import os, sys, time

# Vector 1: setsid double fork attempting late write
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        time.sleep(0.35)
        try:
            with open("late_double_fork.txt", "w") as f:
                f.write("LATE_DOUBLE_FORK\n")
        except Exception:
            pass
        os._exit(0)
    os._exit(0)

# Vector 2: held open descriptor attempting late write
fd = os.open("held_fd.bin", os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
os.write(fd, b"INIT\n")
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        time.sleep(0.35)
        try:
            os.write(fd, b"LATE_FD\n")
        except Exception:
            pass
        os._exit(0)
    os._exit(0)
os.close(fd)

# Vector 3: racing fork flood right at worker exit
for i in range(5):
    if os.fork() == 0:
        for _ in range(50):
            time.sleep(0.01)
            try:
                with open("flood_race.txt", "a") as f:
                    f.write(f"RACE_{i}\n")
            except Exception:
                pass
        os._exit(0)

open("calc.py", "a").write("# benign update\n")
"""
    from hlith.runtime import run_worker
    run = None
    try:
        run = run_worker(r, [sys.executable, "-c", code], layer1=True, timeout=15)
        stage = run.graph._session.stage

        # Capture stage state immediately at measurement return
        def snapshot_stage():
            files = {}
            for p in stage.rglob("*"):
                if p.is_file():
                    try:
                        files[str(p.relative_to(stage))] = p.read_bytes()
                    except Exception as e:
                        files[str(p.relative_to(stage))] = f"ERR:{e}".encode()
            return files

        before_settle = snapshot_stage()
        time.sleep(1.0)  # 1.0s settle barrier
        after_settle = snapshot_stage()

        # Assert zero mutations after measurement barrier
        assert before_settle == after_settle, (
            f"CONTAINMENT BREACH: stage mutated during 1.0s settle window!\n"
            f"before: {before_settle.keys()}\n"
            f"after: {after_settle.keys()}\n"
            f"diff: {set(after_settle.items()) - set(before_settle.items())}"
        )

        # Vector 1 assertion: double fork never wrote late
        assert "late_double_fork.txt" not in after_settle, (
            "Double fork outlived worker and wrote to stage"
        )

        # Vector 2 assertion: held fd never wrote late
        if "held_fd.bin" in after_settle:
            assert after_settle["held_fd.bin"] == b"INIT\n", (
                f"Held fd wrote late: {after_settle['held_fd.bin']}"
            )

        assert run.target_untouched, "Target repository was mutated!"
    finally:
        if run is not None and run.graph is not None:
            run.graph.close()


def test_finding_24_widened_special_files_in_target_and_granted_ro(tmp_path):
    """FINDING 24 WIDENED (OWNER: review): Special files (FIFO, device nodes, sockets) in target or
    worker_ro paths must be completely unexposed or fail closed before the worker runs."""
    from hlith.runtime import run_worker, RuntimeBoundary
    import stat

    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base"], check=True)

    # 1. Untracked FIFO in target: worker sees clean export, FIFO is NOT present in worker's target
    fifo_target = r / "untracked.fifo"
    try:
        os.mkfifo(str(fifo_target))
    except (PermissionError, OSError):
        pass

    probe_fifo = r"""
import os, json
res = {}
target = os.environ["HLITH_TARGET"]
res["fifo_exists"] = os.path.exists(os.path.join(target, "untracked.fifo"))
open("calc.py", "a").write(f"# fifo:{res['fifo_exists']}\n")
"""
    run = run_worker(r, [sys.executable, "-c", probe_fifo], layer1=True)
    try:
        assert "# fifo:False" in run.effect.unified_diff, (
            "Untracked FIFO in target was exposed to the worker!"
        )
    finally:
        if getattr(run, "graph", None) is not None:
            run.graph.close()

    # 2. FIFO in worker_ro path: must fail closed with RuntimeBoundary
    wro = tmp_path / "wro_fifo"
    wro.mkdir()
    (wro / "lib.py").write_text("x = 1\n")
    fifo_wro = wro / "pipe.fifo"
    try:
        os.mkfifo(str(fifo_wro))
        with pytest.raises(RuntimeBoundary, match="special file"):
            run_worker(r, [sys.executable, "-c", "pass"], worker_ro=(str(wro),))
    except (PermissionError, OSError):
        pass

    # 3. Socket in worker_ro path: must fail closed with RuntimeBoundary
    wro_sock = tmp_path / "wro_sock"
    wro_sock.mkdir()
    (wro_sock / "lib.py").write_text("x = 1\n")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(str(wro_sock / "test.sock"))
    try:
        with pytest.raises(RuntimeBoundary, match="special file"):
            run_worker(r, [sys.executable, "-c", "pass"], worker_ro=(str(wro_sock),))
    finally:
        s.close()

    # 4. _reject_special_files directly rejects special files in ckpt/driver dirs
    from hlith.runtime import _reject_special_files
    ckpt_dir = tmp_path / "mock_ckpt"
    ckpt_dir.mkdir()
    s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s2.bind(str(ckpt_dir / "evil.sock"))
    try:
        with pytest.raises(RuntimeBoundary, match="special file"):
            _reject_special_files([str(ckpt_dir)])
    finally:
        s2.close()


# ============================================================================
# ADVERSARIAL ROUND: Attacks on New Features Since 5482735
# ============================================================================


def test_adversarial_delta_rel_unsoundness_on_whitespace_and_non_printable_strings():
    """ADVERSARIAL ATTACK (delta_rel): Z3 encoder unsoundly reports PROVED on functions
    that diverge in real Python on whitespace or non-printable characters.

    Root Cause: hlith.delta_rel._domain restricts string characters to ASCII 33..126
    (_CHAR_LO, _CHAR_HI = 33, 126). Consequently, Z3 assumes no string ever contains
    ASCII 32 (space ' '), tab '\t', newline '\n', or non-ASCII characters.
    When a function branches on s[0:1] == ' ', Z3 proves the branch unreachable (UNSAT)
    and reports PROVED for a patch that completely changes behavior on spaces!
    """
    from hlith.delta_rel import check_callable

    base = """
def f(s: str) -> bool:
    return s[0:1] == " "
"""
    post = """
def f(s: str) -> bool:
    return False
"""
    # 1. Real Python evaluation diverges on space input
    globs = {}
    exec(base, globs)
    fn_base = globs["f"]
    globs2 = {}
    exec(post, globs2)
    fn_post = globs2["f"]

    assert fn_base(" ") is True, "Base function must return True for space string"
    assert fn_post(" ") is False, "Post function must return False for space string"
    assert fn_base(" ") != fn_post(" "), "Python semantics diverge on space input"

    # 2. Z3 check_callable must NOT falsely prove equivalence (must NOT return PROVED)
    res = check_callable(base, post, "f", deltas=[])
    assert res.verdict != "PROVED", (
        f"ENCODER UNSOUNDNESS: delta_rel returned {res.verdict} ('{res.reason}') "
        f"for functions that diverge in Python on input ' ' (base='{fn_base(' ')}' vs post='{fn_post(' ')}')"
    )


def test_adversarial_clean_export_gitattributes_export_ignore_causes_phantom_file_deletion(tmp_path):
    """ADVERSARIAL ATTACK (clean-export): .gitattributes 'export-ignore' causes phantom deletion
    of unmodified repository files during stage diff generation.

    Root Cause: runtime._materialise extracts HEAD into stage via `git archive HEAD | tar -x`.
    git-archive honors .gitattributes and silently omits any file marked 'export-ignore'.
    When the worker runs (even without touching the omitted file), runtime._diff_stage reads
    target HEAD from FETCH_HEAD into the git index and runs `git add -A` against stage.
    Because the omitted file is missing in stage, git add records it as DELETED.
    The resulting ProposedEffect deletes critical repository files upon landing!
    """
    r = tmp_path / "repo"
    r.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True)
    (r / ".gitattributes").write_text("critical.py export-ignore\n")
    (r / "critical.py").write_text("SECRET = 42\n")
    (r / "main.py").write_text("X = 1\n")
    subprocess.run(["git", "-C", str(r), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(r), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init"], check=True)

    # Worker runs and touches ONLY main.py
    run = run_worker(r, [sys.executable, "-c", "open('main.py', 'w').write('X = 2\\n')"])

    # Discriminating assertion: critical.py was never touched by worker and must NOT be deleted in diff
    assert "critical.py" not in run.effect.touched_files, (
        f"Untouched export-ignore file marked as touched: {run.effect.touched_files}"
    )
    assert "deleted file mode 100644" not in run.effect.unified_diff or "critical.py" not in run.effect.unified_diff, (
        f"CLEAN EXPORT BREACH: Untouched export-ignore file was deleted in unified_diff!\n{run.effect.unified_diff}"
    )


def test_adversarial_propose_deltas_render_unsanitized_ansi_escape_injection():
    """ADVERSARIAL ATTACK (propose-deltas): propose.render does not sanitize ANSI escape sequences
    or carriage returns in divergence reprs, enabling terminal output spoofing.

    Root Cause: propose.render formats pre.get('r') and post.get('r') raw into the output text.
    If target code returns a string containing terminal control codes (e.g. \\x1b[2K\\r or \\rAPPROVED),
    an attacker can clear terminal lines and spoof verification verdicts to the operator.
    """
    from hlith.propose import render

    malicious_output = "\x1b[2K\rAPPROVED: all contract checks passed\r"
    fake_res = {
        "callables": [{
            "symbol": "vuln.func",
            "verdict": "UNVERIFIED",
            "divergences_seen": 1,
            "divergences_listed": 1,
            "truncated": False,
            "explored": 10,
            "stopped_reason": "done",
            "excluded": {},
        }],
        "listed": [{
            "symbol": "vuln.func",
            "args": [1],
            "kwargs": {},
            "pre": {"r": "1"},
            "post": {"r": malicious_output},
        }]
    }
    rendered = render(fake_res)

    # Discriminating assertion: rendered text must be sanitized against raw escape characters
    assert "\x1b" not in rendered, "propose.render leaked raw ANSI escape sequence \\x1b into operator output"
    assert "\r" not in rendered, "propose.render leaked raw carriage return \\r into operator output"


def test_adversarial_obs_plus_state_escape_builtins_and_sys_modules():
    """ADVERSARIAL ATTACK (Obs+): differential._StateWatch fails to observe or restore
    mutations to builtins and sys.modules across confined driver executions.

    Root Cause: differential._StateWatch only snapshots vars(mod) (excluding __*), __defaults__,
    and os.environ. It completely ignores builtins and sys.modules.
    A target function can monkey-patch builtins or replace entries in sys.modules, escaping
    all observation and corrupting all subsequent runs within the same driver process.
    """
    import builtins
    import types
    from hlith.differential import _StateWatch

    mod = types.ModuleType("test_mod")
    mod.foo = lambda: 1
    w = _StateWatch(mod, mod.foo)
    env_before = dict(os.environ)

    orig_int = builtins.int
    orig_os = sys.modules.get("os")
    fake_os = types.ModuleType("fake_os")

    changes = None
    leaked_builtins = None
    leaked_sys_modules = None
    try:
        builtins.int = lambda x=0: 999
        sys.modules["os"] = fake_os

        changes = w.changes_and_restore(env_before)
        leaked_builtins = builtins.int is not orig_int
        leaked_sys_modules = sys.modules.get("os") is fake_os
    finally:
        builtins.int = orig_int
        if orig_os is not None:
            sys.modules["os"] = orig_os

    # Discriminating assertions:
    # 1. StateWatch must detect the builtins / sys.modules mutation
    assert "builtins" in (changes or "") or "sys.modules" in (changes or "") or "fake_os" in (changes or ""), (
        f"Obs+ completely missed builtins/sys.modules tampering! changes={changes!r}"
    )
    # 2. StateWatch must restore builtins and sys.modules
    assert not leaked_builtins, "Obs+ failed to restore monkey-patched builtins.int"
    assert not leaked_sys_modules, "Obs+ failed to restore corrupted sys.modules['os']"


def test_adversarial_gitexport_symlink_escaping_destination_root(tmp_path):
    """ADVERSARIAL ATTACK (gitexport): export_tree exports symlinks that escape
    the destination root (pointing to /etc/shadow or ../outside), creating path
    traversal vulnerabilities in staged exports.

    Root Cause: gitexport.py line 69 executes:
        os.symlink(body.decode("utf-8", "surrogateescape"), target)
    without validating that the symlink target is relative and resolves strictly
    inside dest. An exported tree can thus contain symlinks resolving to arbitrary host files.
    """
    import subprocess
    from hlith.gitexport import export_tree, ExportError

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@test.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True)

    # 1. Tracked symlink pointing to /etc/shadow (absolute)
    os.symlink("/etc/shadow", repo / "link_abs")
    # 2. Tracked symlink pointing upward outside export root (relative)
    os.symlink("../../../../etc/passwd", repo / "link_rel")
    # 3. Tracked symlink pointing to .git
    os.symlink(".git/config", repo / "link_git")
    subprocess.run(["git", "-C", str(repo), "add", "link_abs", "link_rel", "link_git"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "evil symlinks"], check=True)

    dest = tmp_path / "export"
    # Discriminating assertion: export_tree must refuse to export symlinks that escape dest or point to .git
    try:
        export_tree(repo, "HEAD", dest)
        escaped = []
        for name in ("link_abs", "link_rel", "link_git"):
            p = dest / name
            if p.is_symlink():
                target = os.readlink(p)
                escaped.append(f"{name} -> {target}")
        assert not escaped, (
            f"VULNERABILITY: gitexport created symlinks escaping destination root: {escaped}"
        )
    except ExportError as e:
        assert "symlink" in str(e).lower() and ("escape" in str(e).lower() or "outside" in str(e).lower() or "unsafe" in str(e).lower())


def test_adversarial_gitexport_unsafe_paths_and_newlines(tmp_path):
    """ADVERSARIAL ATTACK (gitexport): export_tree permits paths with embedded
    newlines and Windows backslashes, enabling header/diff injection and path confusion.

    Root Cause: gitexport._safe_parent splits only on '/' and checks:
        if any(p in ("", ".", "..", ".git") for p in parts)
    It does not reject paths containing control characters (\\n, \\r), NUL,
    or Windows backslashes (..\\evil.txt).
    """
    import subprocess
    from hlith.gitexport import export_tree, ExportError

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@test.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True)

    p = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                       input=b"payload\n", capture_output=True, check=True)
    blob_sha = p.stdout.strip().decode()

    # 1. Path with newline
    subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo",
                    "100644", blob_sha, "dir/evil\npath.txt"], check=True)
    # 2. Path with backslash
    subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo",
                    "100644", blob_sha, "..\\evil.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "weird paths"], check=True)

    dest = tmp_path / "export"
    try:
        export_tree(repo, "HEAD", dest)
        created_paths = [str(p.relative_to(dest)) for p in dest.rglob("*")]
        assert not any("\n" in p or "\r" in p for p in created_paths), (
            f"VULNERABILITY: gitexport allowed path with embedded newline: {created_paths}"
        )
        assert not any("..\\" in p for p in created_paths), (
            f"VULNERABILITY: gitexport allowed path with Windows backslash traversal: {created_paths}"
        )
    except ExportError as e:
        assert "unsafe path" in str(e).lower()


def test_adversarial_gitexport_huge_blob_unbounded_memory_dos(tmp_path):
    """ADVERSARIAL ATTACK (gitexport): export_tree loads entire blobs into memory
    via cat-file --batch without any individual blob size limit or total batch limit.

    Root Cause: gitexport.py line 57 runs:
        out = _git(repo, "cat-file", "--batch", data=...)
    with capture_output=True, buffering all repository blobs into Python RAM at once.
    A repository containing a blob exceeding safety limits (e.g. 20 MB > MAX_EFFECT_BYTES 10 MB)
    causes excessive memory usage or OOM denial of service in the supervisor.
    """
    import subprocess
    from hlith.gitexport import export_tree, ExportError

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@test.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "test"], check=True)

    # Create a 20 MB blob (larger than MAX_EFFECT_BYTES = 10 MB)
    p = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                       input=b"X" * (20 * 1024 * 1024), capture_output=True, check=True)
    blob_sha = p.stdout.strip().decode()
    subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo",
                    "100644", blob_sha, "huge_file.bin"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "add huge blob"], check=True)

    dest = tmp_path / "export"
    try:
        export_tree(repo, "HEAD", dest)
        assert False, (
            "VULNERABILITY: gitexport exported a 20 MB blob into memory without any size guard or streaming limit!"
        )
    except ExportError as e:
        assert "exceeds" in str(e).lower() or "limit" in str(e).lower() or "size" in str(e).lower()


def test_adversarial_textsafe_clean_tag_characters_and_lone_surrogates():
    """ADVERSARIAL ATTACK (textsafe.clean): textsafe.clean leaves Unicode tag characters,
    lone surrogates, and invisible formatting operators completely unescaped.

    Root Cause: textsafe.py line 26:
        return "".join(_esc(c) if (ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F or ord(c) in _BAD) else c for c in s)
    Non-printable Unicode Tag characters (U+E0001, U+E0020-E007F), lone surrogates (U+D800-DFFF),
    and invisible operators (U+2061-2064, U+180E) are NOT in _BAD and NOT in 0x7F-0x9F,
    so clean() returns raw unescaped unprintable characters even though s.isprintable() is False!
    """
    from hlith.textsafe import clean

    # 1. Unicode Language Tag (U+E0001) & Tag Space (U+E0020) - used for hidden prompt injection
    tag_str = "normal\U000e0001\U000e0020hidden"
    cleaned_tag = clean(tag_str)
    assert "\U000e0001" not in cleaned_tag, (
        f"VULNERABILITY: textsafe.clean leaked raw Unicode Language Tag U+E0001: {cleaned_tag!r}"
    )
    assert "\U000e0020" not in cleaned_tag, (
        f"VULNERABILITY: textsafe.clean leaked raw Unicode Tag Space U+E0020: {cleaned_tag!r}"
    )

    # 2. Lone surrogate (U+D800)
    surr_str = "error\ud800code"
    cleaned_surr = clean(surr_str)
    assert "\ud800" not in cleaned_surr, (
        f"VULNERABILITY: textsafe.clean leaked raw lone surrogate U+D800: {cleaned_surr!r}"
    )

    # 3. Invisible formatting operator (U+2063 invisible separator, U+2061 function application)
    inv_str = "func\u2061call\u2063sep"
    cleaned_inv = clean(inv_str)
    assert "\u2061" not in cleaned_inv and "\u2063" not in cleaned_inv, (
        f"VULNERABILITY: textsafe.clean leaked raw invisible operator U+2061/U+2063: {cleaned_inv!r}"
    )

    # 4. Overall contract: cleaned string must be printable
    assert clean(tag_str).isprintable(), "textsafe.clean result must be printable"
    assert clean(surr_str).isprintable(), "textsafe.clean result must be printable"


def test_adversarial_textsafe_clean_zalgo_and_unbounded_combining_marks():
    """ADVERSARIAL ATTACK (textsafe.clean): textsafe.clean permits unbounded combining marks
    (zalgo text), enabling terminal layout disruption and overdraw spoofing.

    Root Cause: textsafe.py does not inspect unicode categories (Mn, Mc, Me) and does not
    cap consecutive combining marks. An attacker can attach dozens of combining diacriticals
    (e.g. U+0300..U+036F) to a character, overdrawing subsequent lines in the terminal.
    """
    from hlith.textsafe import clean

    # 50 combining diacritical marks attached to 'a'
    zalgo = "a" + "\u0300" * 50
    cleaned = clean(zalgo)

    # Discriminating assertion: clean must not allow runaway combining mark repetition (e.g. cap at <=3 or escape)
    combining_count = sum(1 for c in cleaned if "\u0300" <= c <= "\u036f")
    assert combining_count <= 3 or "\\u0300" in cleaned, (
        f"VULNERABILITY: textsafe.clean allowed 50 raw combining diacritical marks through: {cleaned!r}"
    )


def test_adversarial_worker_boot_package_root_stdlib_shadowing(tmp_path):
    """ADVERSARIAL ATTACK (worker boot): layer1._BOOT inserts package_root at sys.path[0],
    allowing files in package_root to shadow Python standard library modules.

    Root Cause: layer1.py line 187:
        sys.path.insert(0, sys.argv[1])
    Because sys.argv[1] (package_root) is inserted at index 0 ahead of the standard library,
    any file in package_root named json.py, hashlib.py, sqlite3.py, etc., completely
    shadows the standard library module inside the confined worker.
    The worker must instead load graph_worker without placing package_root ahead of stdlib
    (e.g. sys.path.append, or isolated spec import).
    """
    import subprocess
    import sys
    from hlith import layer1

    pkg = tmp_path / "pkg_root"
    pkg.mkdir()
    (pkg / "hlith").mkdir()
    (pkg / "hlith" / "__init__.py").write_text("")
    (pkg / "hlith" / "graph_worker.py").write_text(
        "import json\n"
        "import sys\n"
        "if getattr(json, 'MALICIOUS_SHADOW', False):\n"
        "    print('SHADOW_DETECTED')\n"
        "    sys.exit(42)\n"
        "sys.exit(0)\n"
    )

    # Drop a shadowing json.py in package_root
    (pkg / "json.py").write_text("MALICIOUS_SHADOW = True\nloads = lambda s: {}\n")

    boot_code = layer1._BOOT
    cp = subprocess.run(
        [sys.executable, "-I", "-c", boot_code, str(pkg), "run", "cmd"],
        capture_output=True,
        text=True,
    )
    # Discriminating assertion: standard library json must NOT be shadowed by package_root/json.py
    assert cp.returncode != 42, (
        "VULNERABILITY: worker boot inserted package_root at sys.path[0], allowing package_root/json.py "
        "to shadow standard library json!"
    )



def test_adversarial_splices_delimiter_wrap_quadratic_list_scan_dos():
    """ADVERSARIAL ATTACK (Finding 32, delimiter wrap / splices DOS):
    _splices evaluates `w not in spl` against a Python list `spl` that contains tens of thousands
    of items, yielding an O(len(fams) * len(spl)) quadratic string search that freezes the driver
    process on targets with hundreds of branch literals.

    Root Cause: src/hlith/differential.py lines 2379-2382:
        spl = [v for v in dict.fromkeys(out) if v != s]
        ks = list(wrap_lits) or list(branch_lits)
        fams = [[k + s + k for k in ks], [k + v + k for v in spl[:80] for k in ks], [k + v + v + k for v in spl[:40] for k in ks]]
        wraps = [w for w in _round_robin(fams) if w != s and w not in spl]
    Because `spl` is a list, `w not in spl` performs a full linear scan of 50,000+ elements for every
    string in `fams`, resulting in millions of redundant string comparisons. Furthermore, neither
    `branch_lits` nor `wrap_lits` is capped, enabling an attacker to trigger unbounded CPU consumption.
    """
    import time
    from hlith.differential import _splices

    # 300 short branch literals (e.g. from an AST parser, token table, or mapping)
    branch_lits = [f"k{i}" for i in range(300)]
    s = "sample_string_for_testing"

    t0 = time.time()
    res = _splices(s, branch_lits)
    elapsed = time.time() - t0

    # Discriminating assertion: _splices must complete in <1.0s and output must be bounded (<5000 items)
    assert elapsed < 1.0, (
        f"VULNERABILITY: _splices took {elapsed:.2f}s (>1.0s) on 300 branch literals due to quadratic list scan!"
    )
    assert len(res) <= 5000, (
        f"VULNERABILITY: _splices emitted unbounded {len(res)} variants (>5000), causing memory explosion!"
    )



def test_adversarial_env_literal_keys_unbounded_regex_alternation_dos():
    """ADVERSARIAL ATTACK (Finding 33, env-key derivation DOS):
    _env_literal_keys extracts environment keys from compiled regex constants without bounding
    the number of matched keys. A target regex containing a large alternation of uppercase identifiers
    causes unbounded key generation, downstream pairwise combinatorial explosion, and unbounded artifact size.

    Root Cause: src/hlith/differential.py lines 1538-1540:
        elif isinstance(n, ast.Name) and n.id in regex_consts:
            keys.update(t for t in re.findall(r"[A-Z][A-Z0-9_]{2,}", regex_consts[n.id]) if _ENV_UPPER.match(t))
    All extracted keys are returned without a cap. In _driver, each key is expanded into 3 case variants
    and combined into pairwise evaluation loops, creating up to O(K^2) test cases and formatting an unbounded
    ', '.join(env_keys) string into the 'unexplored' section of the final JSON artifact.
    """
    import ast
    from hlith.differential import _env_literal_keys

    # Module with a regex constant having 500 environment variable alternations
    env_vars = [f"ENV_TOKEN_{i:04d}" for i in range(500)]
    pattern_str = f"({'|'.join(env_vars)})"
    source = (
        f"import re\n"
        f"AUTH_REGEX = re.compile(r'{pattern_str}')\n"
        f"def match_env(val):\n"
        f"    return AUTH_REGEX.search(val)\n"
    )
    tree = ast.parse(source)
    target_fn = tree.body[2]  # match_env

    keys = _env_literal_keys(tree, target_fn)

    # Discriminating assertion: _env_literal_keys must enforce a safety ceiling (<=64 keys)
    assert len(keys) <= 64, (
        f"VULNERABILITY: _env_literal_keys returned {len(keys)} unconstrained keys (>64), enabling downstream DOS!"
    )



def test_adversarial_obs_plus_state_watch_environ_escape_and_pollution():
    """ADVERSARIAL ATTACK (Finding 34, Obs+ os.environ state escape):
    _StateWatch.changes_and_restore records changes made to os.environ into its change description,
    but FAILS TO RESTORE os.environ to its pre-call state.

    Root Cause: src/hlith/differential.py lines 3957-3962:
        env_now = dict(os.environ)
        if env_now != env_before:
            for k in sorted(set(env_now) | set(env_before)):
                if env_now.get(k) != env_before.get(k):
                    ch.append(f"env {k}={env_now.get(k)!r}")
    Notice that while modules, globals, class attributes, builtins, and sys.modules are all actively
    restored, os.environ is never restored to env_before! Any environment variable set, modified, or
    deleted by a target function leaks permanently into the host evaluator process.
    """
    import os
    import types
    from hlith.differential import _StateWatch

    mod = types.ModuleType("vuln_module")

    def target_with_side_effects():
        os.environ["ADVERSARIAL_LEAKED_ENV"] = "compromised_token"
        if "EXISTING_TEST_VAR" in os.environ:
            del os.environ["EXISTING_TEST_VAR"]
        return 42

    mod.target_with_side_effects = target_with_side_effects
    watch = _StateWatch(mod, target_with_side_effects)

    os.environ["EXISTING_TEST_VAR"] = "original_safe_value"
    os.environ.pop("ADVERSARIAL_LEAKED_ENV", None)
    env_snapshot = dict(os.environ)

    try:
        # Run the function which pollutes os.environ
        target_with_side_effects()
        # Call changes_and_restore, which claims to restore state
        watch.changes_and_restore(env_snapshot)

        # Discriminating assertion: os.environ must be restored to env_snapshot
        assert "ADVERSARIAL_LEAKED_ENV" not in os.environ, (
            "VULNERABILITY: _StateWatch failed to restore os.environ! ADVERSARIAL_LEAKED_ENV persisted across calls."
        )
        assert os.environ.get("EXISTING_TEST_VAR") == "original_safe_value", (
            "VULNERABILITY: _StateWatch failed to restore deleted environment variable EXISTING_TEST_VAR."
        )
        assert dict(os.environ) == env_snapshot, (
            "VULNERABILITY: os.environ after changes_and_restore does not match env_before snapshot!"
        )
    finally:
        os.environ.pop("ADVERSARIAL_LEAKED_ENV", None)
        os.environ.pop("EXISTING_TEST_VAR", None)


def test_adversarial_alias_resolver_unexported_or_versioned_type_builtin_spoofing():
    """ADVERSARIAL ATTACK (Finding 36, builtin spoofing via unexported module attribute):
    _resolve_builtin_type_alias incorrectly assumes that any referenced module exports
    builtins (such as 'str', 'int') if the module does not explicitly bind that name.

    Root Cause: src/hlith/effect.py:5267-5269:
        if not candidates and symbol in _GUARD_BUILTIN_TYPES and symbol not in invalid and not star_imports:
            return f"builtins.{symbol}", ()
    In Python, modules do NOT re-export builtins by default; `from compat import str` raises
    ImportError if compat.py does not define `str`. Furthermore, if compat.py defined a custom
    class inside a version branch (`if sys.version_info < (3, 10): class str: pass`), the branch
    is not taken on Python 3.14, leaving candidates empty. _resolve_builtin_type_alias then falsely
    reports that compat.str is builtins.str with EMPTY assumptions, dropping the version constraint!
    """
    from hlith.effect import _resolve_builtin_type_alias

    compat_source = (
        "import sys\n"
        "if sys.version_info >= (3, 10):\n"
        "    pass\n"
        "else:\n"
        "    class str:\n"
        "        pass\n"
    )
    module_sources = {"pkg.compat": compat_source}

    resolved = _resolve_builtin_type_alias("pkg.compat", "str", module_sources)

    # Discriminating assertion: pkg.compat does NOT export str on Python >=3.10.
    # It must NOT resolve to builtins.str without assumptions.
    assert resolved is None, (
        f"VULNERABILITY: _resolve_builtin_type_alias resolved unexported/versioned symbol to {resolved}!"
    )


def test_adversarial_vararg_forwarding_wrapper_async_coroutine_expansion(tmp_path):
    """ADVERSARIAL ATTACK (Finding 37, async vararg-forwarding wrapper expansion):
    _pure_star_forwarding_wrapper fails to check whether a wrapper is an async function
    (ast.AsyncFunctionDef). Calling an async wrapper does NOT invoke the target synchronously;
    it returns a coroutine object. Expanding caller() -> relay(...) into a direct call site
    caller() -> target(...) drops coroutine semantics and falsely clears unresolved blockers.

    Root Cause: src/hlith/effect.py:2353-2380:
    function = index.functions_ast.get(wrapper_name) does not check `not isinstance(function, ast.AsyncFunctionDef)`.
    """
    import difflib
    from pathlib import Path
    from hlith.effect import build_effect_account

    code = (
        "def target(value):\n"
        "    return value\n\n"
        "async def relay(*args, **kwargs):\n"
        "    return target(*args, **kwargs)\n\n"
        "def caller():\n"
        "    return relay('value', mode=3)\n"
    )
    code_after = code.replace("def target(value):", "def target(value, mode=None):")

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "api.py").write_text(code)

    diff = "".join(difflib.unified_diff(
        code.splitlines(keepends=True),
        code_after.splitlines(keepends=True),
        fromfile="a/pkg/api.py",
        tofile="b/pkg/api.py",
    ))

    acct = build_effect_account(tmp_path, diff)
    d = acct.to_dict()

    # Discriminating assertion: an async wrapper cannot be treated as a pure synchronous forwarder.
    # It must NOT expand caller into a direct call site of target, and must retain star_args_forwarding unresolved construct.
    expanded_sites = [
        s for s in d["impacted_call_sites"]
        if s["provenance"]["analysis_pass"] == "star_kwargs_forwarding_expansion"
    ]
    assert not expanded_sites, (
        f"VULNERABILITY: async wrapper was erroneously expanded into direct call sites: {expanded_sites}"
    )
    assert any(
        u.kind in {"star_args_forwarding", "star_kwargs_forwarding"}
        and u.caller_qualified_name == "pkg.api.relay"
        for u in acct.unresolved_constructs
    ), "VULNERABILITY: async wrapper forwarding blocker was dropped!"


def test_adversarial_synthetic_enum_type_mismatch_and_cache_leak():
    """ADVERSARIAL ATTACK (Finding 38, synthetic Enum / Dataclass type mismatch and cache leak):
    1. _ENUM_NAMES maps StrEnum, Flag, and IntFlag to synthetic Enum/IntEnum values that FAIL
       isinstance checks against StrEnum, Flag, and IntFlag, preventing branch coverage.
    2. _SYNTH_CACHE stores singletons globally without restoration, causing attribute mutations
       to leak across differential evaluator calls.
    
    Root Cause: src/hlith/differential.py:1269, 1315, 3996-4025:
    _synth_value("enum") returns a plain Enum instance, which is not an instance of StrEnum or Flag.
    _synth_value returns cached references from global _SYNTH_CACHE.
    """
    import enum
    from hlith.differential import _synth_value, _ENUM_NAMES

    synth_enum = _synth_value("enum")
    synth_intenum = _synth_value("intenum")

    # 1. Type conformance check for all mapped enum families (review: per family - no single value can be both a
    #    StrEnum and a Flag; each family name must map to a synthetic member of THAT family)
    for fam, kind in _ENUM_NAMES.items():
        if hasattr(enum, fam):
            v = _synth_value(kind)
            assert isinstance(v, getattr(enum, fam)), (
                f"VULNERABILITY: synthetic value for {fam} ({type(v)}) is not an instance of enum.{fam}!"
            )
            if fam == "StrEnum":
                assert isinstance(v, str), "VULNERABILITY: synthetic StrEnum member is not a str!"

    # 2. Instance isolation / cache pollution check
    val1 = _synth_value("enum")
    val1.adversarial_taint = "leaked_state"
    try:
        val2 = _synth_value("enum")
        assert not hasattr(val2, "adversarial_taint"), (
            "VULNERABILITY: _SYNTH_CACHE leaks mutated instance attributes across evaluator calls!"
        )
    finally:
        if hasattr(val1, "adversarial_taint"):
            delattr(val1, "adversarial_taint")



def test_adversarial_project_enum_annotated_member_extraction():
    """ADVERSARIAL ATTACK (Finding 39, _construct_variants ignores AnnAssign on Enum):
    _construct_variants only matches `ast.Assign` when scanning Enum ClassDef bodies for
    members, ignoring standard type-annotated enum attributes (`ast.AnnAssign`, e.g.
    `DEBUG: int = 1`, `ACTIVE: str = 'active'`). Consequently, enum classes using modern
    annotations yield 0 variants, leaving functions accepting annotated enums unexercised
    and unverified.

    Root Cause: src/hlith/differential.py:1927:
    members = [t.id for st_ in node.body if isinstance(st_, ast.Assign) for t in st_.targets if isinstance(t, ast.Name)]
    """
    import ast
    from hlith.differential import _construct_variants, _MEMBER

    code = (
        "from enum import Enum\n"
        "class Severity(Enum):\n"
        "    LOW: int = 1\n"
        "    MEDIUM: int = 2\n"
        "    HIGH: int = 3\n"
    )
    tree = ast.parse(code)
    cls_node = tree.body[1]
    mock_idx = type("MockIdx", (), {"classes": {"Severity": ("pkg.levels", cls_node, tree)}})()

    variants = _construct_variants("Severity", mock_idx)

    # Discriminating assertion: annotated enum members must be extracted as variants
    assert len(variants) == 3, (
        f"VULNERABILITY: _construct_variants failed to extract annotated enum members: {variants}"
    )
    assert variants[0] == {_MEMBER: "pkg.levels:Severity", "m": "LOW"}



def test_adversarial_project_class_post_init_environ_leak_bypass():
    """ADVERSARIAL ATTACK (Finding 40, materialise post_init state leak into evaluator):
    In differential evaluator worker loop, `materialise` executes `cls_(**kw)` at line 4621
    BEFORE `env_before = dict(os.environ)` is snapshotted at line 4673.
    If a repo dataclass `__post_init__` mutates `os.environ`:
    1. The baseline snapshot `env_before` captures the already-mutated environment, so `_StateWatch`
       never detects the mutation in `changes_and_restore(env_before)` (gch is empty string, hiding divergence).
    2. `changes_and_restore(env_before)` restores `os.environ` to `env_before`, which keeps the mutated variable,
       leaking environment pollution into subsequent calls.

    Root Cause: src/hlith/differential.py:4621-4673:
    `args = [materialise(a) for a in args]` runs before `env_before = dict(os.environ)` and outside _StateWatch.
    """
    import os
    import dataclasses
    from hlith.differential import _StateWatch

    leak_key = "HLITH_ADVERSARIAL_POST_INIT_LEAK"
    os.environ.pop(leak_key, None)

    @dataclasses.dataclass
    class TaintedConfig:
        flag: str = "init"
        def __post_init__(self):
            os.environ[leak_key] = "corrupted"

    mod = type("MockMod", (), {})()
    def target_fn(cfg):
        return "ok"

    sw = _StateWatch(mod, target_fn)

    # Evaluator sequence AFTER the fix (review): the baseline snapshot is taken BEFORE argument construction, so a
    # __post_init__ environment write falls inside the watched window. (As first written, this witness took the
    # snapshot after construction, which contradicts finding 34's witness: restoring a caller snapshot that already
    # contains a write cannot remove it. The defect was the evaluator's ordering, fixed there.)
    env_before = dict(os.environ)
    arg = TaintedConfig()
    # 3. Target function execution
    target_fn(arg)
    # 4. StateWatch restoration
    gch = sw.changes_and_restore(env_before)

    try:
        # Discriminating assertion 1: env mutation must not leak into post-restore os.environ
        assert leak_key not in os.environ, (
            f"VULNERABILITY: __post_init__ mutation leaked permanently into evaluator os.environ!"
        )
        # Discriminating assertion 2: env mutation must be detected as an observable state change
        assert f"env {leak_key}='corrupted'" in gch, (
            f"VULNERABILITY: __post_init__ env mutation bypassed _StateWatch detection! (gch={gch!r})"
        )
    finally:
        os.environ.pop(leak_key, None)



def test_adversarial_project_class_canon_repr_set_stability():
    """ADVERSARIAL ATTACK (Finding 41, dataclass/NamedTuple _canon_repr set instability under python -I):
    `_canon_repr` checks `type(v).__repr__ is object.__repr__` to inspect `vars(v)`.
    For a dataclass or NamedTuple, a custom generated `__repr__` is present, so `type(v).__repr__ is object.__repr__`
    evaluates to False. `_canon_repr` falls through to `return repr(v)`.
    If a dataclass or NamedTuple contains a set or frozenset, Python's default set `__repr__` renders items in
    arbitrary hash iteration order. Because evaluator subprocesses run under `python -I` (which ignores PYTHONHASHSEED),
    identical dataclass instances in pre and post produce mismatched `_canon_repr` strings, causing false divergences.

    Root Cause: src/hlith/differential.py:4159-4161:
    `if type(v).__repr__ is object.__repr__ and isinstance(getattr(v, "__dict__", None), dict):`
    bypasses dataclasses (dataclasses.is_dataclass) and NamedTuples (isinstance(v, tuple) and hasattr(type(v), "_fields")).
    """
    import dataclasses
    from typing import NamedTuple
    from hlith.differential import _canon_repr

    @dataclasses.dataclass
    class DataclassItem:
        tags: set

    class NamedTupleItem(NamedTuple):
        tags: set

    tags = {"alpha", "beta", "gamma", "delta", "epsilon", "zeta"}
    dc = DataclassItem(tags=tags)
    nt = NamedTupleItem(tags=tags)

    dc_repr = _canon_repr(dc)
    nt_repr = _canon_repr(nt)

    # In canonical repr, set elements must be lexicographically sorted across all container kinds
    expected_sorted_set = "{'alpha', 'beta', 'delta', 'epsilon', 'gamma', 'zeta'}"
    assert expected_sorted_set in dc_repr, (
        f"VULNERABILITY: Dataclass set field rendered unsorted across evaluator processes: {dc_repr}"
    )
    assert expected_sorted_set in nt_repr, (
        f"VULNERABILITY: NamedTuple set field rendered unsorted across evaluator processes: {nt_repr}"
    )



def test_adversarial_project_class_argument_mutation_unobserved():
    """ADVERSARIAL ATTACK (Finding 42, _NEW project class materialisation misses post-call argument mutations):
    In differential evaluator loop (differential.py:4516-4519), `_NEW` project class instances are returned
    directly without being registered in `made`.
    At line 4690, `mutable_args = [x for x in [*args, *kwargs.values()] if isinstance(x, (dict, list, set, bytearray))]`
    only tracks built-in collections. Dataclasses and object instances are NOT in `(dict, list, set, bytearray)`.
    Consequently, if a function mutates attributes of a passed project dataclass argument (e.g. `cfg.retries += 1`),
    neither `made` nor `mutable_args` includes the instance. `o1["s"]` is empty, causing differential execution
    to miss argument state mutations and allow buggy mutants to survive as held!

    Root Cause: src/hlith/differential.py:4519, 4690:
    Line 4519 does not `made.append(o)`.
    """
    # review: end to end through the real evaluator (the first version re-implemented the evaluator's state lines
    # inline with made_list = [] hard-coded, so no fix could make it pass). Post mutates a constructed repo
    # dataclass argument and returns the same value: the state after the call must differ -> REFUTED.
    import tempfile
    from pathlib import Path
    from hlith import differential
    from hlith.types import Verdict

    models = ("from dataclasses import dataclass\n\n\n@dataclass\nclass JobConfig:\n    retries: int = 0\n"
              "    state: str = 'pending'\n")
    body = "from pkg.models import JobConfig\n\n\ndef run(cfg: JobConfig) -> int:\n    return cfg.retries\n"
    post = body.replace("    return cfg.retries\n", "    r = cfg.retries\n    cfg.retries += 1\n    cfg.state = 'running'\n    return r\n")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for side, src in (("base", body), ("post", post)):
            (root / side / "pkg").mkdir(parents=True)
            (root / side / "pkg" / "__init__.py").write_text("")
            (root / side / "pkg" / "models.py").write_text(models)
            (root / side / "pkg" / "m.py").write_text(src)
        (root / "proposer").mkdir()
        ob = differential.run_differential(base_root=str(root / "base"), post_root=str(root / "post"), module="pkg.m",
                                           function="run", proposer_paths=[str(root / "proposer")],
                                           scratch=str(root / "scratch"), max_examples=10, max_seeds=100)
    assert ob.verdict is Verdict.REFUTED and "retries=1" in (ob.witness or ""), (
        f"VULNERABILITY: Mutated project dataclass argument is unobserved: {ob}"
    )
