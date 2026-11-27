"""case (TUI truth + terminals), red-first.
(1) Claim must not say READY when the state directory cannot be written: since the lazy run-dir change (case) planning creates nothing, so the early
    'Permission denied' disappeared. Readiness now checks writability of the nearest existing ancestor WITHOUT creating anything; Run is unavailable with the real reason.
(2) A terminal that cannot run the screen (TERM empty / dumb / unknown) takes the PLAIN path: the frame as text, exit 0, no alternate-screen sequence, never a hang."""
import os
import pty
import re
import select
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hlith.operator.tui import host, launch
from hlith.operator.tui.model import ViewState

ROOT = Path(__file__).resolve().parents[1]


def _git(cwd, *a):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *a], capture_output=True, text=True, check=True).stdout


@pytest.fixture()
def toy(tmp_path):
    r = tmp_path / "src-repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    (r / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    return r, state


def _plan(r, state):
    patch = _git(r, "diff").encode()
    return launch.plan(r, patch_bytes=patch, manifest_obj={"paths": {"calc.py": ["modify"]}}, manifest_bytes=b'{"paths": {"calc.py": ["modify"]}}',
                       base_rev=_git(r, "rev-parse", "HEAD").strip(), label="t", state=state, target_python=sys.executable)


# ------------------------------------------------------------------ (1) readiness under a read-only state directory
def test_planning_with_a_read_only_state_directory_fails_with_permission_denied_and_creates_nothing(toy):
    r, state = toy
    os.chmod(state, stat.S_IRUSR | stat.S_IXUSR)
    try:
        before = sorted(state.rglob("*"))
        with pytest.raises(PermissionError) as e:
            _plan(r, state)
        assert "Permission denied" in str(e.value)
        assert sorted(state.rglob("*")) == before == []
    finally:
        os.chmod(state, stat.S_IRWXU)


def test_the_claim_context_is_not_runnable_and_names_the_cause_when_the_state_directory_is_read_only(toy, monkeypatch):
    r, state = toy
    monkeypatch.setenv("HLITH_UI_STATE", str(state))
    ctx = host._repo_context(r)
    st = host._selection_context(ctx, ViewState(st="selection", cols=100, rows=30, focusIndex=0))
    os.chmod(state, stat.S_IRUSR | stat.S_IXUSR)
    try:
        claimed = host._claim_context({**st, "claim_excluded": [], "claim_file_total": 1, "can_run": True})
    finally:
        os.chmod(state, stat.S_IRWXU)
    assert claimed["can_run"] is False and claimed.get("plan") is None and claimed.get("command") is None
    assert "Permission denied" in str(claimed["change"].get("note", ""))


def test_control_a_writable_state_directory_is_ready_and_planning_still_creates_nothing(toy):
    r, state = toy
    p = _plan(r, state)
    assert not p.run_dir.exists() and list(state.rglob("*")) == []


def test_a_state_path_below_a_missing_directory_is_judged_by_the_nearest_existing_ancestor(toy):
    r, state = toy
    deep = state / "not" / "yet" / "there"
    p = _plan(r, deep)  # writable ancestor: fine, nothing created
    assert not deep.exists() and p.run_dir.parts[: len(deep.parts)] == deep.parts
    os.chmod(state, stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(PermissionError):
            _plan(r, deep)
    finally:
        os.chmod(state, stat.S_IRWXU)


# ------------------------------------------------------------------ (2) terminals that cannot run the screen
def test_terminal_capability_decision():
    # curses.setupterm only takes effect on its FIRST call per process (as in the real host), so each TERM is judged in a fresh interpreter
    code = "import sys; from hlith.operator.tui import host; print(host._terminal_can_run_screen({'TERM': sys.argv[1]} if sys.argv[1] != '<unset>' else {}))"
    for term, ok in (("xterm-256color", True), ("screen-256color", True), ("dumb", False), ("", False), ("unknown-term-xyz", False), ("<unset>", False)):
        cp = subprocess.run([sys.executable, "-c", code, term], capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
        assert cp.stdout.strip() == str(ok), (term, cp.stdout, cp.stderr[-200:])


def _run_tty(argv, env, seconds=25, rows=24, cols=80):
    import fcntl
    import struct
    import termios

    m, s = pty.openpty()
    fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    p = subprocess.Popen(argv, stdin=s, stdout=s, stderr=s, env=env, start_new_session=True, close_fds=True)
    os.close(s)
    buf = bytearray()
    end = time.monotonic() + seconds
    while time.monotonic() < end and p.poll() is None:
        if select.select([m], [], [], 0.1)[0]:
            try:
                buf.extend(os.read(m, 65536))
            except OSError:
                break
    rc = p.poll()
    hung = rc is None
    if hung:
        p.kill()
        p.wait()
    try:
        while select.select([m], [], [], 0.1)[0]:
            buf.extend(os.read(m, 65536))
    except OSError:
        pass
    os.close(m)
    return rc, hung, bytes(buf)


@pytest.mark.parametrize("term", ["dumb", "", "unknown-term-xyz"])
def test_a_terminal_that_cannot_run_the_screen_prints_the_plain_frame_and_exits_0(toy, tmp_path, term):
    r, _state = toy
    env = {k: v for k, v in os.environ.items() if k not in ("TERM", "NO_COLOR")}
    env.update({"PYTHONPATH": str(ROOT / "src"), "HLITH_UI_STATE": str(tmp_path / "st"), "GIT_CEILING_DIRECTORIES": str(tmp_path.parent)})
    if term != "<unset>":
        env["TERM"] = term
    t0 = time.monotonic()
    rc, hung, raw = _run_tty([sys.executable, "-m", "hlith.operator.tui", "--repo", str(r)], env)
    text = raw.decode("utf-8", "replace")
    assert not hung, f"TERM={term!r}: the host never exited (a stranger on a dumb terminal would hang):\n{text[-300:]}"
    assert rc == 0, (term, rc, text[-300:])
    assert "\x1b[?1049h" not in text and "\x1b[H\x1b[2J" not in text, "no alternate-screen switch / screen clear may be sent"
    assert "Traceback" not in text and "Uncommitted work" in text and "Review change" in text, text[-400:]  # the plain frame
    assert time.monotonic() - t0 < 20


def test_control_a_capable_terminal_still_opens_the_screen(toy, tmp_path):
    r, _state = toy
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "HLITH_UI_STATE": str(tmp_path / "st"), "TERM": "xterm-256color", "GIT_CEILING_DIRECTORIES": str(tmp_path.parent)}
    env.pop("NO_COLOR", None)
    rc, hung, raw = _run_tty([sys.executable, "-m", "hlith.operator.tui", "--repo", str(r)], env, seconds=6)
    assert hung, "a capable terminal keeps the interactive screen open (it must NOT exit on its own)"
    assert b"\x1b[?1049h" in raw


def test_the_claim_ready_row_never_says_ready_when_run_is_unavailable(toy, monkeypatch):
    """case: the READY row next to the action must agree with the action: with no runnable plan it says so (and why), never 'ready · the check can start'."""
    from dataclasses import replace

    from hlith.operator.tui import frame

    r, state = toy
    monkeypatch.setenv("HLITH_UI_STATE", str(state))
    ctx = host._repo_context(r)
    st = ViewState(st="selection", cols=100, rows=30, focusIndex=0)
    ctx = host._selection_context(ctx, st)
    os.chmod(state, stat.S_IRUSR | stat.S_IXUSR)
    try:
        claimed = host._claim_context({**ctx, "claim_excluded": [], "claim_file_total": 1, "can_run": True})
    finally:
        os.chmod(state, stat.S_IRWXU)
    art = host._preview_artifact(dict(host._EMPTY), claimed, False)
    for cols, rows in ((100, 30), (80, 24)):
        text = "\n".join(frame.render(replace(st, st="claim", cols=cols, rows=rows), cols, rows, art, context=claimed).text_rows())
        flat = " ".join(text.split())
        assert "Run unavailable" in flat and "Permission denied" in flat
        assert "the check can start on this host" not in flat, flat
        assert "READY no" in flat or "READY  no" in text, text
