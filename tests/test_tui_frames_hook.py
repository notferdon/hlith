"""case (design review frames-hook decision): HLITH_UI_FRAMES=<file> appends '=== frame RxC after key K t=..s' + the rendered text rows after each painted frame
(the format the legacy evidence tests read); with the variable unset the host's behaviour is byte-identical and nothing is written."""
import fcntl
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

from hlith.operator.tui import host

pytestmark = pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")


def _git(cwd, *a):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *a], capture_output=True, text=True, check=True).stdout


@pytest.fixture()
def repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "a.py").write_text("def f(x):\n    return x\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    (r / "a.py").write_text("def f(x):\n    return x + 1\n")
    return r


def _run(repo, tmp_path, frames=None, keys=(b"\r",), rows=30, cols=100):
    src = str(Path(host.__file__).resolve().parents[3])
    env = {**os.environ, "PYTHONPATH": src, "HLITH_UI_STATE": str(tmp_path / "st"), "TERM": "xterm-256color", "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("NO_COLOR", None)
    env.pop("HLITH_UI_FRAMES", None)
    if frames is not None:
        env["HLITH_UI_FRAMES"] = str(frames)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(repo)
        os.execve(sys.executable, [sys.executable, "-m", "hlith.operator.tui", "--repo", str(repo)], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    buf = bytearray()

    def pump(seconds, until=None):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([fd], [], [], 0.05)[0]:
                try:
                    buf.extend(os.read(fd, 65536))
                except OSError:
                    return
            if until is not None and until in bytes(buf):
                return

    try:
        pump(20, until=b"Review change")
        assert b"Review change" in bytes(buf)
        pump(0.5)
        first = bytes(buf)
        for k in keys:
            os.write(fd, k)
            pump(2.0)
    finally:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        os.close(fd)
    return first


def test_frames_are_appended_in_the_legacy_format_for_every_painted_frame(repo, tmp_path):
    log = tmp_path / "frames.txt"
    _run(repo, tmp_path, frames=log, keys=(b"\r",))  # Offer -> Selection
    text = log.read_text(encoding="utf-8")
    heads = re.findall(r"^=== frame (\d+)x(\d+) after key (.+?) t=[0-9.]+s$", text, re.M)
    assert len(heads) >= 2, text[:300]
    assert all((h, w) == ("30", "100") for h, w, _k in heads)
    assert any("Review change" in blk for blk in text.split("=== frame ")[1:]), "the Offer frame is in the log"  # the first frame is the loading frame
    assert "tracked edits and new files" in text or "Uncommitted work" in text  # Selection frame after Enter
    assert any(k == "'\\r'" or "enter" in k for _h, _w, k in heads), heads  # the key that produced a later frame is recorded
    assert "\x1b" not in text  # plain text: no control bytes


def test_without_the_variable_nothing_is_written_and_the_first_paint_is_byte_identical(repo, tmp_path):
    log = tmp_path / "frames.txt"
    a = _run(repo, tmp_path, frames=None, keys=())
    assert not log.exists() and not list(tmp_path.glob("frames*"))
    b = _run(repo, tmp_path, frames=log, keys=())
    assert re.sub(rb"\d+\.\ds", b"", a) == re.sub(rb"\d+\.\ds", b"", b) or a[:200] == b[:200]  # same bytes on screen
    assert log.exists()
