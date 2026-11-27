# SPDX-License-Identifier: Apache-2.0
"""Process lifecycle for a headless engine: it must not outlive the client that asked for the run (case).

``die_with_parent()`` is called once by an engine that has NO operator of its own (``--surface-mode headless``, i.e. ``hlith
check``). A TUI-launched engine is deliberately detachable and never calls it. When the parent process is gone (killed, crashed,
SIGHUP'd terminal, ``timeout`` expiry of a harness) the engine ends its own descendants and exits, leaving the launch folder
without an artifact: a lost run reads as lost, never as a verdict.

Three independent triggers, because each alone has a hole: PR_SET_PDEATHSIG (kernel, immediate, but fires on the death of the
parent THREAD and runs in the main thread only between bytecodes), a daemon watcher thread polling ``getppid()`` (also covers a
main thread stuck in a long C call that never returns to the interpreter's signal check), and SIGTERM/SIGHUP (a polite stop).
Descendants are found from /proc at the moment of need (never from stored pids) and every signal goes through a pidfd opened
after the pid's start time was read twice, so a reused pid is never signalled."""

from __future__ import annotations

import ctypes
import os
import signal
import threading
import time

PR_SET_PDEATHSIG = 1
_started = False


def _stat_fields(pid: int) -> list[str] | None:
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return None


def descendants(root: int) -> list[tuple[int, str]]:
    """(pid, start time) of every live descendant of ``root``, read from /proc now."""
    kids: dict[int, list[int]] = {}
    for d in os.listdir("/proc"):
        if d.isdigit():
            f = _stat_fields(int(d))
            if f and f[0] != "Z":
                kids.setdefault(int(f[1]), []).append(int(d))
    out, todo = [], list(kids.get(root, []))
    while todo:
        p = todo.pop()
        f = _stat_fields(p)
        if f:
            out.append((p, f[19]))
            todo.extend(kids.get(p, []))
    return out


def _kill_verified(pid: int, start: str) -> None:
    """SIGKILL ``pid`` only if it is still the process whose start time we read (no reused pid)."""
    try:
        fd = os.pidfd_open(pid)
    except OSError:
        return
    try:
        f = _stat_fields(pid)
        if f and f[19] == start:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
    except OSError:
        pass
    finally:
        os.close(fd)


def kill_descendants(root: int | None = None, rounds: int = 6) -> int:
    """SIGKILL the whole descendant tree of ``root`` (default: this process), repeating while new children appear."""
    root = os.getpid() if root is None else root
    total = 0
    for _ in range(rounds):
        found = descendants(root)
        if not found:
            break
        total += len(found)
        for pid, start in found:
            _kill_verified(pid, start)
        time.sleep(0.05)
    return total


def _terminate(code: int = 143) -> None:
    try:
        kill_descendants()
    finally:
        os._exit(code)


def die_with_parent(poll: float = 0.5) -> None:
    """Idempotent. Install the three triggers described in the module docstring."""
    global _started
    if _started:
        return
    _started = True
    parent = os.getppid()
    try:
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, int(signal.SIGTERM), 0, 0, 0)
    except OSError:
        pass
    if os.getppid() != parent:  # the parent died before the trigger was armed
        _terminate()

    def on_signal(_signum, _frame) -> None:
        _terminate()

    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, on_signal)

    def watch() -> None:
        while True:
            time.sleep(poll)
            if os.getppid() != parent:
                _terminate()

    threading.Thread(target=watch, name="case", daemon=True).start()
