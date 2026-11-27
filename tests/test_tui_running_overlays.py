# SPDX-License-Identifier: Apache-2.0
"""case (review): Running-screen overlays on the REAL launch path (clone, wrapper, launch dir; only the engine argv is swapped for 'sleep 600').

Proven green: Esc never stops a run, q (detach) / x (cancel) / ? dialogs default to Stay/Keep, keys typed under a dialog act on it only, detach exits the host
and the run keeps going. RED (measured on 554765e1 and 35c63ae0): the cancel dialog advertises '[ Cancel run ] enter' but Enter does nothing: the host has no
cancel handler at all, the run stays alive and the dialog stays painted."""

from __future__ import annotations

import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

from test_tui_claim_pgdn import E, LONG_PYTHON, PGDN, _make_repo

TAB = b"\t"
_WRAP = r'''
import dataclasses, os, sys
from hlith.operator.tui import host, launch
real_start = launch.start
def sleep_start(plan, **k):
    try:
        plan = dataclasses.replace(plan, argv=["sleep", "600"])
    except Exception:
        plan.argv = ["sleep", "600"]
    return real_start(plan, **k)
launch.start = sleep_start
sys.exit(host.main(["--repo", os.environ["N7_REPO"], "--target-python", os.environ["N7_PY"]]))
'''


def _alive(pid):
    try:
        os.kill(pid, 0)
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[0] != "Z"  # a killed, unreaped child is dead
    except (ProcessLookupError, OSError):
        return False


def _running(tmp_path, extra):
    """Start a real (sleeping) run from the Claim, then type `extra`; return (frame text, run alive, host exited)."""
    repo = _make_repo(tmp_path)
    (tmp_path / "w.py").write_text(_WRAP)
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"), PYTHONDONTWRITEBYTECODE="1", TERM="xterm-256color", N7_REPO=str(repo),
               N7_PY=LONG_PYTHON, XDG_STATE_HOME=str(tmp_path / "xdg"), HLITH_UI_STATE=str(tmp_path / "state"))
    env.pop("NO_COLOR", None)
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(sys.executable, [sys.executable, str(tmp_path / "w.py")], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    buf = bytearray()

    def pump(d):
        end = time.monotonic() + d
        while time.monotonic() < end:
            if select.select([fd], [], [], 0.02)[0]:
                try:
                    buf.extend(os.read(fd, 65536))
                except OSError:
                    return

    strip = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")
    run_pid = None
    try:
        pump(1.2)
        end0 = time.monotonic() + 20
        while b"review change" not in strip.sub(b"", bytes(buf)) and time.monotonic() < end0:
            pump(0.1)
        pump(0.3)
        script = [E, 0.8, E, 1.0, b"c", 0.6] + [x for _ in range(3) for x in (PGDN, 0.4)] + [b"\x1b", 0.9, E, 2.0] + list(extra)  # Offer, Selection, Claim, command review (c, PgDn to its end, esc), start
        for k in script:
            if isinstance(k, float):
                pump(k)
            else:
                os.write(fd, k)
                pump(0.12)
        pump(0.5)
        metas = list((tmp_path / "state").glob("**/launch-*/meta.json"))
        assert metas, "no run was started"
        run_pid = json.loads(metas[-1].read_text())["pid"]
        alive = _alive(run_pid)
        r_, _st = os.waitpid(pid, os.WNOHANG)
        exited = bool(r_)
    finally:
        for p in (pid,):
            try:
                os.kill(p, signal.SIGKILL)
                os.waitpid(p, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
        subprocess.run(["pkill", "-f", str(tmp_path) + "/"], capture_output=True)
        os.close(fd)
    last = bytes(buf).decode("utf-8", "replace").split("\x1b[H\x1b[2J")[-1]
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", last).replace("\r", ""), alive, exited


pytestmark = pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")


@pytest.mark.parametrize("name,extra", [
    ("esc", [b"\x1b", 0.5]),
    ("enter-x5", [x for _ in range(5) for x in (E, 0.15)]),
    ("detach-dialog-esc", [b"q", 0.5, b"\x1b", 0.6]),
    ("detach-dialog-enter-stays", [b"q", 0.5, E, 0.6]),
    ("cancel-dialog-esc", [b"x", 0.5, b"\x1b", 0.6]),
    ("cancel-dialog-enter-keeps", [b"x", 0.5, E, 0.8]),
    ("cancel-dialog-tab-esc", [b"x", 0.5, TAB, 0.3, b"\x1b", 0.6]),
    ("keys-under-the-detach-dialog", [b"q", 0.5] + [x for k in (PGDN, b"d", b"w", b"p", b"u", b"x") for x in (k, 0.2)] + [b"\x1b", 0.6]),
    ("help-esc", [b"?", 0.5, b"\x1b", 0.6]),
    ("diff-drill-esc", [b"d", 0.6, b"\x1b", 0.6]),
])
def test_running_screen_never_stops_the_run_without_an_explicit_confirm(tmp_path, name, extra):
    text, alive, exited = _running(tmp_path, extra)
    assert alive and not exited, f"{name}: the run was stopped or the host left without an explicit confirm"
    assert "CHECKING" in text or "CANCEL RUN" in text or "DETACH" in text or "KEYS" in text or "DIFF" in text


def test_explicit_detach_leaves_the_host_and_the_run_keeps_going(tmp_path):
    text, alive, exited = _running(tmp_path, [b"q", 0.5, TAB, 0.3, E, 1.5])
    assert exited and alive


def test_RED_explicit_cancel_stops_the_run_the_dialog_promises(tmp_path):
    """x, Tab (focus '[ Cancel run ]'), Enter: the dialog says 'The clone is discarded and no decision is recorded'. Measured: nothing happens, the run
    stays alive and the dialog stays painted (the host has no cancel handler; reduce leaves vs unchanged). Either implement the cancel or stop advertising it."""
    text, alive, exited = _running(tmp_path, [b"x", 0.5, TAB, 0.3, E, 2.0])
    assert not alive, "Enter on '[ Cancel run ]' left the run running"
    assert "CANCEL RUN" not in text, "the cancel dialog is still painted after Enter"
