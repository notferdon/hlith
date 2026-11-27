"""case: entering Claim must NOT create a launch-* run directory (History would report a run that never existed as LOST).
The directory is created lazily by launch.start; planning (Claim) leaves the state directory byte-for-byte unchanged."""
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.operator.tui import host, launch
from hlith.operator.tui.model import ViewState


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


def snapshot(root: Path):
    """The whole tree under the state root: (relative path, mode, size, content digest for files). Any new directory, file or mode change shows."""
    out = []
    for p in sorted([root, *root.rglob("*")]):
        st = p.lstat()
        digest = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() and not p.is_symlink() else ""
        out.append((str(p.relative_to(root)), st.st_mode & 0o7777, st.st_size if p.is_file() else 0, digest))
    return out


def _plan(r, state):
    patch = _git(r, "diff").encode()
    return launch.plan(r, patch_bytes=patch, manifest_obj={"paths": {"calc.py": ["modify"]}}, manifest_bytes=b'{"paths": {"calc.py": ["modify"]}}',
                       base_rev=_git(r, "rev-parse", "HEAD").strip(), label="t", state=state, target_python=sys.executable)


def test_planning_twice_leaves_the_state_tree_byte_for_byte_unchanged(toy):
    r, state = toy
    before = snapshot(state)
    a, b = _plan(r, state), _plan(r, state)
    assert a.run_dir != b.run_dir  # still distinct names
    assert not a.run_dir.exists() and not b.run_dir.exists()
    assert snapshot(state) == before, "planning created something in the state directory"


def test_first_ever_planning_does_not_even_create_the_repository_bucket(toy):
    r, state = toy
    assert list(state.rglob("*")) == []
    _plan(r, state)
    assert list(state.rglob("*")) == [], list(state.rglob("*"))


def test_agent_and_effect_resume_plans_create_nothing_either(toy):
    r, state = toy
    before = snapshot(state)
    rec = {"target": str(r), "thread_store": str(state / "ts"), "thread_id": "th-1", "command": "x", "interrupt_checkpoint_id": "cp-1"}
    launch.plan_agent_resume(r, rec, target_python=sys.executable, state=state)
    launch.plan_agent_resume(r, {**rec, "kind": "effect-interrupt"}, target_python=sys.executable, state=state)
    assert snapshot(state) == before


def test_the_claim_context_and_esc_leave_the_state_directory_unchanged(toy, monkeypatch):
    r, state = toy
    monkeypatch.setenv("HLITH_UI_STATE", str(state))
    ctx = host._repo_context(r)
    st = host._selection_context(ctx, ViewState(st="selection", cols=100, rows=30, focusIndex=0))
    before = snapshot(state)
    claimed = host._claim_context({**st, "claim_excluded": [], "claim_file_total": 1, "can_run": True})
    assert claimed.get("plan") is not None
    assert snapshot(state) == before, "entering Claim wrote to the state directory"
    # History after the Claim visit lists nothing (RED before the fix: one LOST row per visit)
    assert launch.run_rows_with_summary(state, r)[0] == [], launch.run_rows_with_summary(state, r)[0]  # History scoped to this repository: no run


def _sleeper(p):
    return dataclasses.replace(p, argv=[sys.executable, "-c", "import time; time.sleep(30)"])


def test_start_creates_no_run_dir_and_history_lists_nothing(toy):
    """Was: start() created the launch folder privately (0700) and History listed it once. Review-only (product.REVIEW_ONLY): start() is
    unavailable, so the state tree stays byte-for-byte unchanged and History lists no run for a check that never started."""
    r, state = toy
    p = _sleeper(_plan(r, state))
    before = snapshot(state)
    meta = launch.start(p)
    assert meta["state"] == launch.UNAVAILABLE_STATE and meta["run_id"] == p.run_id and "hlith check" in meta["reason"]
    assert not p.run_dir.exists() and snapshot(state) == before, "start created something in the state directory"
    assert [x for x in launch.run_rows(state) if x["run_id"] == p.run_id] == [] and launch.run_rows(state) == []


def test_starting_the_same_plan_twice_creates_and_overwrites_nothing(toy):
    """Was: a second start() of one plan raised FileExistsError and kept the first meta.json. Review-only: both calls are unavailable and
    neither creates nor overwrites anything."""
    r, state = toy
    p = _sleeper(_plan(r, state))
    before = snapshot(state)
    assert launch.start(p)["state"] == launch.UNAVAILABLE_STATE
    assert launch.start(p)["state"] == launch.UNAVAILABLE_STATE
    assert not p.run_dir.exists() and snapshot(state) == before


# ------------------------------------------------------------------ real PTY: before / after listing of the state directory
import fcntl  # noqa: E402
import pty  # noqa: E402
import select  # noqa: E402
import signal  # noqa: E402
import struct  # noqa: E402
import termios  # noqa: E402
import time  # noqa: E402


def _drive(toy, keys_with_waits, rows=30, cols=100):
    """Run the real host under a pty with a scratch state directory; return (snapshots taken after each step, raw screen bytes)."""
    r, state = toy
    src = str(Path(host.__file__).resolve().parents[3])
    env = {**os.environ, "PYTHONPATH": src, "HLITH_UI_STATE": str(state), "TERM": "xterm-256color", "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("NO_COLOR", None)
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(r)
        os.execve(sys.executable, [sys.executable, "-m", "hlith.operator.tui", "--repo", str(r)], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    buf = bytearray()
    snaps = []
    seen = []

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
        assert b"Review change" in bytes(buf), "the Offer never painted"
        pump(0.5)
        snaps.append(snapshot(state))
        for key, wait, marker in keys_with_waits:
            buf.clear()
            os.write(fd, key)
            pump(wait, until=marker)
            seen.append(bytes(buf))
            snaps.append(snapshot(state))
    finally:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        os.close(fd)
    return snaps, seen


def test_pty_claim_then_esc_esc_leaves_the_state_directory_listing_identical(toy):
    E, ESC = b"\r", b"\x1b"
    snaps, seen = _drive(toy, [(E, 5, b"Uncommitted"), (E, 8, b"Review command"), (ESC, 1.5, None), (ESC, 1.5, None)])
    assert b"Review command" in seen[1], "the Claim was never reached: the test would pass vacuously"
    before = snaps[0]
    assert all(s == before for s in snaps[1:]), [len(s) for s in snaps]  # Selection, Claim, back, back: nothing created
    assert not any("launch-" in row[0] for s in snaps for row in s), "a launch-* folder appeared"


def test_pty_history_after_visiting_claim_lists_no_run(toy):
    r, state = toy
    E, ESC = b"\r", b"\x1b"
    _snaps, seen = _drive(toy, [(E, 5, b"Uncommitted"), (E, 8, b"Review command"), (ESC, 1.0, None), (ESC, 1.0, None)])
    assert b"Review command" in seen[1], "the Claim was never reached: the test would pass vacuously"
    assert launch.run_rows_with_summary(state, r)[0] == [], launch.run_rows_with_summary(state, r)[0]  # History scoped to this repository: no run
