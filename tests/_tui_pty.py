"""Drive a program in a real pseudo-terminal (stdlib pty) and return the raw transcript; no emulator dependency."""
import fcntl
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time

ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-B]|\x1b[=>78]")


def strip(b: bytes) -> str:
    return ANSI.sub(b"", b).decode("utf-8", "replace")


def run_pty(argv, keys=(), rows=24, cols=70, env=None, cwd=None, settle=0.5, boot=2.0, timeout=60):
    m, s = pty.openpty()
    fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    e = {**os.environ, "TERM": "xterm-256color", "ESCDELAY": "25", "LINES": str(rows), "COLUMNS": str(cols), **(env or {})}
    p = subprocess.Popen(argv, stdin=s, stdout=s, stderr=s, env=e, cwd=cwd, start_new_session=True, close_fds=True)
    os.close(s)
    out = bytearray()
    marks: list[tuple[str, int]] = []

    def drain(quiet, fixed=False, cap=None):
        t_start = time.monotonic()
        hard = t_start + (cap if cap is not None else (quiet if fixed else max(4 * quiet, 2.0)))  # a screen that redraws by itself never goes quiet
        end = t_start + quiet
        while time.monotonic() < min(end, hard):
            r, _, _ = select.select([m], [], [], 0.05)
            if r:
                try:
                    d = os.read(m, 65536)
                except OSError:
                    return
                if not d:
                    return
                out.extend(d)
                if not fixed:  # a quiet period: more output extends it (up to the hard cap above)
                    end = time.monotonic() + quiet

    drain(boot)
    t_ready = time.monotonic() + 40
    while not out and time.monotonic() < t_ready and p.poll() is None:  # under load the program may still be starting: keys sent now would be lost
        drain(0.3, fixed=True)
    for k in keys:
        marks.append((k, len(out)))
        if k.startswith("~until:"):  # "~until:TEXT:SECONDS": read until TEXT is on the screen (a real run takes as long as it takes)
            _t, text, secs = k.split(":", 2)[0], k[7:].rsplit(":", 1)[0], float(k.rsplit(":", 1)[1])
            end = time.monotonic() + secs
            while time.monotonic() < end and text not in strip(bytes(out)[marks[-1][1]:]):
                drain(0.3, fixed=True)
            continue
        if k.startswith("~wait:"):  # not a key: keep reading for N seconds (the real engine is running)
            drain(float(k[6:]), fixed=True)
            continue
        os.write(m, k.encode())
        drain(settle)
    t0 = time.monotonic()
    while p.poll() is None and time.monotonic() - t0 < timeout:
        drain(0.2)
    if p.poll() is None:
        p.kill()
    rc = p.wait()
    os.close(m)
    return rc, bytes(out), marks
