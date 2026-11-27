# SPDX-License-Identifier: Apache-2.0
"""case (review): the Claim screen may enable Run only after EVERY row of the exact command was painted.

RED 10: PgDn moves by rows-5, which can exceed the visible body, so the first PgDn can bring the
"END OF COMMAND" row on screen while command rows in between were never painted. These tests are
test-only: they drive the real host/frame/reduce with a real git repository and a fake launcher
(nothing is cloned, no engine starts).

Layers
  1. geometry matrix (pure frame/reduce): 80x24 is RED on 23dc4b86; 90x26 100x28 92x26 80x30 pass;
     60x20 80x16 are fail-closed (the command is never painted, so Run is unreachable).
  2. host PTY (pty.fork, launch.start replaced by a marker writer): Run starts only after the end
     row AND the dwell; forged marker text, resize and SIGSTOP/SIGCONT never start a run.
  3. negative controls: a deliberately wrong behaviour must make the checker fail.

Contract on the merged layout (EXACT COMMAND below READINESS; measured by a real pty with a fake start, 82a8e3cc):
the command end needs TWO PgDn at both 100x30 and 80x24. Enter after PgDn x0 = 0 starts, x1 = 0, x2 = 1, x3 = 1, x4 = 1;
a refused Enter shows the toast 'Scroll to the end first (PgDn)'. Start-gate semantics (Enter before the end = 0, after = 1) are
unchanged; only the number of PgDn in the positive control depends on geometry.
"""

from __future__ import annotations

import fcntl
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import textwrap
import time
from pathlib import Path

import pytest

from hlith.operator.tui import frame, host, launch, model, reduce

END = "END OF COMMAND · review marker"
LONG_PYTHON = "/" + "/".join(f"longdirectorynamesegment{n}" for n in range(14)) + "/bin/python"
# a much longer interpreter path: gives the command enough wrapped rows that an explicit rows-5 step really skips one (used by the checker control)
VERY_LONG_PYTHON = "/" + "/".join(f"longdirectorynamesegment{n}" for n in range(45)) + "/bin/python"
E = b"\r"
PGDN = b"\x1b[6~"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   check=True, capture_output=True, text=True)


def _make_repo(root: Path, subject_c3: str = "c3") -> Path:
    r = root / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    for n, subject in ((1, "c1"), (2, "c2"), (3, subject_c3)):
        (r / "a.py").write_text(f"a={n}\n")
        _git(r, "add", ".")
        _git(r, "commit", "-qm", subject)
    return r


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(launch, "start", lambda *a, **k: pytest.fail("start must not be called"))
    return _make_repo(tmp_path)


def _claim(repo: Path, cols: int, rows: int, target_python: str | None = LONG_PYTHON, pick: str = "c3"):
    ctx = host._repo_context(repo, (), target_python)
    i = next(n for n, s in enumerate(ctx["sources"]) if s["kind"] == "commit" and pick in s["label"])
    st = model.ViewState(st="claim", focusIndex=0, selectedIndex=i, included=True, cols=cols, rows=rows, drill="command")  # case: the argv lives on the dedicated command-review page
    c = host._claim_context(host._selection_context(ctx, st))
    c = {**c, "claim_command_seen": False}
    return st, c, host._preview_artifact(dict(host._EMPTY), c, False), i


def _truth_rows(c, art, i, cols):
    """The command rows exactly as the frame wraps them (a 200-row render shows every row)."""
    tall = frame.render(model.ViewState(st="claim", focusIndex=0, selectedIndex=i, included=True, cols=cols, rows=200, drill="command"),
                        cols, 200, art, elapsed=0, sample=False, context=c, color="plain").text_rows()
    t = [r.strip() for r in tall]
    a = next(k for k, r in enumerate(t) if r.startswith("EXACT COMMAND"))
    b = next(k for k, r in enumerate(t) if r == END or (cols < len(END) and r.startswith("END OF COMMAND")))  # a narrow pane wraps the marker
    return [r for r in t[a + 1:b] if r]


def _pages(st, c, art, cols, rows, step=None, limit=14):
    """Paint each PgDn page; return (rows painted so far at the first END-visible paint, scroll, pages) or None."""
    shown: set[str] = set()
    s = st
    for n in range(limit):
        r = frame.render(s, cols, rows, art, elapsed=0, sample=False, context=c, color="plain")
        shown.update(x.strip() for x in r.text_rows())
        if host._command_end_visible(r):
            return shown, s.scroll, n
        nxt = step(s) if step else reduce.reduce(s, "key:pgdn")
        if nxt.scroll == s.scroll:
            return None
        s = nxt
    return None


# ---------------------------------------------------------------- 1. geometry matrix
@pytest.mark.parametrize("cols,rows", [(90, 26), (100, 28), (92, 26), (80, 30), (80, 16), (60, 20), (64, 24), (64, 60), (56, 24), (48, 20), (48, 16), (25, 58), (25, 24), (20, 24)])
def test_every_command_row_is_painted_before_the_end_row_counts_as_seen(repo, cols, rows):
    st, c, art, i = _claim(repo, cols, rows)
    truth = _truth_rows(c, art, i, cols)
    assert len(truth) >= 15, "the fixture command must be long enough to need scrolling" if rows < 40 else "the FULL argv"
    got = _pages(st, c, art, cols, rows)
    assert got is not None, "the END row must be reachable by PgDn at this geometry"
    shown, _scroll, _pages_n = got
    assert [r for r in truth if r not in shown] == []


def test_RED10_80x24_pgdn_must_not_skip_command_rows(repo):
    """RED on 23dc4b86: the first PgDn (scroll 19) shows END while two command rows were never painted."""
    st, c, art, i = _claim(repo, 80, 24)
    truth = _truth_rows(c, art, i, 80)
    got = _pages(st, c, art, 80, 24)
    assert got is not None
    shown, scroll, _n = got
    missing = [r for r in truth if r not in shown]
    assert not missing, f"END row visible at scroll={scroll} but command rows never painted: {missing[:3]}"


@pytest.mark.parametrize("cols,rows", [(25, 4), (10, 2), (3, 2), (1, 1)])  # panes with no room for ANY command row: nothing is painted, so Run can never enable (every other screen still navigates)
def test_small_terminals_fail_closed_the_command_is_never_painted_and_run_never_enables(repo, cols, rows):
    st, c, art, i = _claim(repo, cols, rows)
    s = st
    for _ in range(12):
        r = frame.render(s, cols, rows, art, elapsed=0, sample=False, context=c, color="plain")
        assert host._command_end_visible(r) is False
        assert host._command_visible(r, c["command"]) is False
        s = reduce.reduce(s, "key:pgdn")
    ready = {**c, "claim_command_seen": False, "command_visible": False, "claim_dwell_satisfied": True}
    assert host._start_confirmed(ready, state=st, events=["enter"], claim_shown=False,
                                 claim_painted_at=0.0, read_started_at=5.0, now=6.0) is None


def test_forged_marker_text_in_label_does_not_mark_the_end_seen(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(launch, "start", lambda *a, **k: pytest.fail("start must not be called"))
    r = _make_repo(tmp_path, subject_c3=END)
    st, c, art, i = _claim(r, 80, 24, pick="END OF COMMAND")
    rendered = frame.render(st, 80, 24, art, elapsed=0, sample=False, context=c, color="plain")
    # A layout: the forged label is painted, so a text search would be fooled. B layout (e332978f): the one-row scope drops a long title, so the
    # forged text is not painted at <= 120 columns at all; either way the end row must not count as seen.
    assert host._command_end_visible(rendered) is False


# ---------------------------------------------------------------- 3. negative controls (matrix)
@pytest.mark.parametrize("segments,cols,rows", [(30, 90, 26), (30, 100, 30), (45, 100, 28), (45, 120, 30)])
def test_RED10_longer_commands_skip_rows_at_sizes_that_pass_with_the_default_fixture(repo, segments, cols, rows):
    """RED on 23dc4b86: the defect is not specific to 80x24; the skipped span grows with the command length."""
    tp = "/" + "/".join(f"longdirectorynamesegment{n}" for n in range(segments)) + "/bin/python"
    st, c, art, i = _claim(repo, cols, rows, target_python=tp)
    truth = _truth_rows(c, art, i, cols)
    got = _pages(st, c, art, cols, rows)
    assert got is not None
    missing = [r for r in truth if r not in got[0]]
    assert not missing, f"{len(missing)} command rows never painted before END at {cols}x{rows}: {missing[:2]}"


def test_negative_control_the_checker_flags_an_intentionally_bad_rows_minus_5_step_and_clears_an_overlap(repo):
    """Independent of the product's current PgDn step: the SAME checker must find missing rows for an explicit
    oversized step (rows+8: on the merged layout the product step overlaps, so the old rows-5 mutant no longer skips; this test feeds in a step that does) and none for a rows-12 overlap (positive control)."""
    from dataclasses import replace

    st, c, art, i = _claim(repo, 80, 24, target_python=VERY_LONG_PYTHON)
    truth = _truth_rows(c, art, i, 80)
    bad = _pages(st, c, art, 80, 24, step=lambda s: replace(s, scroll=s.scroll + max(1, s.rows + 8)))
    assert bad is not None
    assert [r for r in truth if r not in bad[0]], "the checker must find rows skipped by an explicit oversized step"
    good = _pages(st, c, art, 80, 24, step=lambda s: replace(s, scroll=s.scroll + max(1, s.rows - 12)))
    assert good is not None
    assert [r for r in truth if r not in good[0]] == []


def test_negative_control_a_text_search_end_check_is_forgeable(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setattr(launch, "start", lambda *a, **k: pytest.fail("start must not be called"))
    r = _make_repo(tmp_path, subject_c3=END)
    st, c, art, i = _claim(r, 80, 24, pick="END OF COMMAND")
    rendered = frame.render(st, 80, 24, art, elapsed=0, sample=False, context=c, color="plain")
    text_search = "".join(END.split()) in "".join("".join(rendered.text_rows()).split())
    if not text_search:
        pytest.skip("B layout: the Claim scope row drops a long title, so the forged marker text is not painted at 80x24 (the attack is closed by layout; "
                    "the unit guard test above still asserts the end flag is false)")
    assert text_search is True, "the old text-search rule would have been fooled: the control proves the test can fail"
    assert host._command_end_visible(rendered) is False


# ---------------------------------------------------------------- 2. host PTY
_WRAP = textwrap.dedent('''
    import os, sys, time
    from hlith.operator.tui import launch, host
    MARK = os.environ["HLITH_TEST_MARK"]
    def fake_start(plan, **k):
        with open(MARK, "a") as f:
            f.write("START %.3f\\n" % time.monotonic())
        return {"run_id": plan.run_id, "state": "started", "argv": plan.argv}
    launch.start = fake_start
    _slow = float(os.environ.get("HLITH_TEST_SLOW", "0"))
    if _slow:
        _orig = host._repo_context
        host._repo_context = lambda *a, **k: (time.sleep(_slow), _orig(*a, **k))[1]
    _rf = os.environ.get("HLITH_TEST_READY_FILE")
    if _rf:
        _real = host._readiness
        def _flip(repo, explicit):
            r, py = _real(repo, explicit)
            if open(_rf).read().strip() == "unavailable":
                b = dict(r.get("boundary") or {})
                b.update(status="unavailable", tone="bad", detail="landlock not reported by this kernel")
                b["causes"] = [{"label": "landlock", "status": "unavailable", "tone": "bad", "detail": "not reported by this kernel"},
                               {"label": "user ns", "status": "ready", "tone": "ok", "detail": "enabled"}]
                r = {**r, "boundary": b}
            return r, py
        host._readiness = _flip
    if not os.environ.get("HLITH_TEST_REAL_STATUS"):  # history tests read the recorded runs for real (a stubbed 'unknown' status hides every run)
        launch.status = lambda d: {"state": "unknown", "why": "fake"}
        launch.live = lambda d: None
    _art = [os.environ["HLITH_TEST_ARTIFACT"]] if os.environ.get("HLITH_TEST_ARTIFACT") else []
    sys.exit(host.main(["--repo", os.environ["HLITH_TEST_REPO"], "--target-python", os.environ["HLITH_TEST_PY"], *_art]))
''')


def _pty_run(tmp_path: Path, repo: Path, script, size=(24, 80), slow: float = 0.0, screen: bool = False, raw: bool = False, ready: str | None = None, artifact: str | None = None, state: str | None = None, keep_no_color: bool = False):
    """Run the real host under a pty, replay `script`, return the number of fake starts. No engine, no clone."""
    wrap = tmp_path / "wrap.py"
    wrap.write_text(_WRAP)
    mark = tmp_path / "mark.txt"
    mark.write_text("")
    if ready:
        (tmp_path / "ready.txt").write_text(ready)
    src = str(Path(host.__file__).resolve().parents[3])
    env = dict(os.environ, PYTHONPATH=src, PYTHONDONTWRITEBYTECODE="1", TERM="xterm-256color",
               HLITH_TEST_ARTIFACT=artifact or "", HLITH_TEST_READY_FILE=str(tmp_path / "ready.txt") if ready else "", HLITH_TEST_MARK=str(mark), HLITH_TEST_REPO=str(repo), HLITH_TEST_PY=LONG_PYTHON, XDG_STATE_HOME=str(tmp_path / "xdg"), HLITH_TEST_SLOW=str(slow))
    if not keep_no_color:
        env.pop("NO_COLOR", None)
    if state:
        env["HLITH_UI_STATE"] = state
        env["HLITH_TEST_REAL_STATUS"] = "1"
    pid, fd = pty.fork()
    if pid == 0:
        os.execve(sys.executable, [sys.executable, str(wrap)], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", size[0], size[1], 0, 0))

    captured = bytearray()

    def pump(dur: float) -> None:
        end = time.monotonic() + dur
        while time.monotonic() < end:
            if select.select([fd], [], [], 0.01)[0]:
                try:
                    captured.extend(os.read(fd, 65536))
                except OSError:
                    return

    try:
        pump(1.2)
        if not slow and not artifact:
            # under load the first paint can come later than 1.2 s and Enters typed while the repository loads are ignored by design:
            # wait (bounded) until the Offer marker was painted. Loading tests (slow > 0) keep their own timing.
            import re as _re0

            end0 = time.monotonic() + 20.0
            while b"review change" not in _re0.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", bytes(captured)) and time.monotonic() < end0:
                pump(0.05)
            pump(0.2)
        for kind, arg in script:
            if kind == "wait":
                pump(arg)
            elif kind == "ready":
                (tmp_path / "ready.txt").write_text(arg)
            elif kind == "until":
                # fresh-bytes rule: only bytes painted AFTER this step began count, so the loading frame cannot satisfy it
                mark_from = len(captured)
                end = time.monotonic() + 30.0
                import re as _re

                def _fresh():
                    return _re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", bytes(captured[mark_from:]))  # SGR between words must not hide the marker

                while arg not in _fresh() and time.monotonic() < end:
                    pump(0.05)
                assert arg in _fresh(), f"marker {arg!r} never painted"
                pump(0.3)
            elif kind == "key":
                os.write(fd, arg)
            elif kind == "sig":
                os.kill(pid, arg)
            elif kind == "size":
                fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", arg[0], arg[1], 0, 0))
        pump(0.8)
    finally:
        for sig in (signal.SIGCONT, signal.SIGKILL):
            try:
                os.kill(pid, sig)
            except OSError:
                pass
        os.waitpid(pid, 0)
        os.close(fd)
    starts = len(mark.read_text().split("START")) - 1
    if raw:
        return starts, bytes(captured)
    if not screen:
        return starts
    import re

    last = captured.decode("utf-8", "replace").split("\x1b[H\x1b[2J")[-1]
    return starts, re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", last).replace("\r", "")


REVIEW = [("key", b"c"), ("wait", 0.5), ("key", PGDN), ("wait", 0.5), ("key", PGDN), ("wait", 0.5), ("key", b"\x1b"), ("wait", 0.9)]  # open the command-review page, page to its END, esc back to the claim, wait out the dwell
OPEN_CLAIM = [("key", E), ("wait", 0.4), ("key", E)]          # Offer -> Selection -> Claim (commit c3 is source 1)
OPEN_CLAIM_C3 = [("key", E), ("wait", 0.4), ("key", b"\x1b[B"), ("wait", 0.1), ("key", E)]


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_80x24_run_starts_only_after_the_end_row_and_the_dwell_and_never_skips_rows(tmp_path, monkeypatch):
    """Control + red in one: PgDn, wait past the dwell, Enter. A start is allowed ONLY if no command row was
    skipped. On 23dc4b86 the long command skips rows at 80x24, so this FAILS (it starts)."""
    repo = _make_repo(tmp_path)
    starts = _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9), *REVIEW, ("key", E)], (24, 80))
    st, c, art, i = _claim(repo, 80, 24)
    truth = _truth_rows(c, art, i, 80)
    got = _pages(st, c, art, 80, 24)
    skipped = bool(got) and any(r not in got[0] for r in truth)
    assert not (starts and skipped), "Run started although command rows were never painted"


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_enter_without_scrolling_never_starts_at_80x24(tmp_path):
    repo = _make_repo(tmp_path)
    assert _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9), ("key", E), ("wait", 0.6)], (24, 80)) == 0


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_enter_right_after_the_end_row_appears_is_ignored_by_the_dwell(tmp_path):
    repo = _make_repo(tmp_path)
    assert _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9), ("key", b"c"), ("wait", 0.5), ("key", PGDN), ("wait", 0.5), ("key", PGDN), ("wait", 0.4), ("key", b"\x1b"), ("wait", 0.1), ("key", E)], (30, 100)) == 0


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_resize_that_hides_the_command_end_restarts_the_review(tmp_path):
    """After END was seen at 100x30, shrink to 80x24 (the old scroll no longer shows every command row / END):
    Enter after the dwell must NOT start; the operator has to review again at the new geometry."""
    repo = _make_repo(tmp_path)
    assert _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9), *REVIEW,
                                     ("size", (24, 80)), ("wait", 0.9), ("key", E)], (30, 100)) == 0


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_enter_queued_while_stopped_then_continued_never_starts(tmp_path):
    repo = _make_repo(tmp_path)
    assert _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9), *REVIEW,
                                     ("sig", signal.SIGSTOP), ("wait", 0.3), ("key", E), ("wait", 0.4),
                                     ("sig", signal.SIGCONT), ("wait", 0.8)], (30, 100)) == 0


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_forged_marker_subject_never_starts_without_the_real_end(tmp_path):
    repo = _make_repo(tmp_path, subject_c3=END)
    assert _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9), ("key", E), ("wait", 0.8)], (24, 80)) == 0


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_negative_control_a_clean_scroll_then_enter_does_start_at_100x30(tmp_path):
    """Control: with a geometry where PgDn skips nothing, the same keys DO start a run, so the zeros above are meaningful."""
    repo = _make_repo(tmp_path)
    assert _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9), *REVIEW, ("key", E)], (30, 100)) == 1


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_enters_typed_while_the_repository_loads_leave_the_offer_screen(tmp_path):
    """WEAK 11: two Enters during the (3 s, injected) repository read must not advance Offer -> Selection -> Claim."""
    repo = _make_repo(tmp_path)
    starts, text = _pty_run(tmp_path, repo, [("key", E), ("wait", 0.2), ("key", E), ("wait", 3.6)], (30, 100), slow=3.0, screen=True)
    assert starts == 0
    assert ("CHANGE TO REVIEW" in text or "Review change" in text) and "Review command" not in text and "EXACT COMMAND" not in text, text[:400]  # A Offer heading or the B Offer button


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_negative_control_the_same_two_enters_after_the_load_do_reach_claim(tmp_path):
    """Control: with the repository loaded the same two Enters DO reach Claim, so the screen check above can fail. Waits for the Offer marker
    (fresh bytes after the loading frame), not a fixed sleep: the injected 3 s delay starts after interpreter startup, so a clock from spawn races."""
    repo = _make_repo(tmp_path)
    starts, text = _pty_run(tmp_path, repo, [("until", b"review change"), ("key", E), ("wait", 0.4), ("key", E), ("wait", 0.8)], (30, 100), slow=3.0, screen=True)
    assert starts == 0
    assert "Review command" in text, text[:400]


# ---------------------------------------------------------------- 4. the 'd' (diff) key and a hostile patch
@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
@pytest.mark.parametrize("where", ["claim-after-end", "claim-before-end"])
def test_pty_d_then_enter_starts_nothing(tmp_path, where):
    """'d' opens the diff page from Claim; Enter there starts nothing and the screen stays on the diff page (the gate, not the key, decides Run)."""
    repo = _make_repo(tmp_path)
    to_end = [("wait", 0.9), *REVIEW] if where == "claim-after-end" else [("wait", 0.9)]
    starts, text = _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, *to_end, ("key", b"d"), ("wait", 0.7), ("key", E), ("wait", 0.8)], (30, 100), screen=True)
    assert starts == 0, "d then Enter must not start a run"
    assert "DIFF · a.py" in text, text[:300]


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_esc_from_the_diff_page_returns_to_claim(tmp_path):
    repo = _make_repo(tmp_path)
    starts, text = _pty_run(tmp_path, repo, [*OPEN_CLAIM_C3, ("wait", 0.9), ("key", b"d"), ("wait", 0.7), ("key", b"\x1b"), ("wait", 1.0)], (30, 100), screen=True)
    assert starts == 0
    assert "Review command" in text and "DIFF · a.py" not in text, text[:300]


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_hostile_patch_lines_are_escaped_never_emitted_raw(tmp_path):
    """An uncommitted change whose lines carry OSC/ANSI/BEL: the screen shows them escaped and emits no control sequence of its own making
    (only the host's CSI), stays alive, and does not paint megabytes."""
    import re

    repo = _make_repo(tmp_path)
    (repo / "a.py").write_text("\n".join(["x=1", "\x1b]0;PWNED-TITLE\x07", "\x1b[31mred\x1b[0m", "bell\x07", "y=ok"]) + "\n")
    starts, raw = _pty_run(tmp_path, repo, [("key", E), ("wait", 1.0), ("key", b"d"), ("wait", 1.5)], (30, 100), raw=True)
    assert starts == 0
    stripped = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", raw)
    assert b"\x1b" not in stripped and b"\x07" not in stripped, stripped[:80]
    assert b"\\x1b]0;PWNED-TITLE" in raw, "the hostile line must be visible, escaped"
    assert len(raw) < 1_000_000, len(raw)


# ---------------------------------------------------------------- 5. the pre-run boundary block (readiness unavailable) can only REMOVE starts
_TO_END = REVIEW
_FLIP_CASES = {
    "unavailable-full-journey": ("unavailable", [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("key", E), ("wait", 0.8)]),
    "unavailable-enter-spam": ("unavailable", [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END] + [x for _ in range(20) for x in (("key", E), ("wait", 0.03))] + [("wait", 0.8)]),
    "unavailable-r-spam-then-enter": ("unavailable", [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("key", E), ("wait", 0.5)] + [x for _ in range(20) for x in (("key", b"r"), ("wait", 0.03))] + [("key", E), ("wait", 0.8)]),
    "flip-after-the-claim-paint-before-enter": ("ready", [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("ready", "unavailable"), ("key", E), ("wait", 0.8)]),
    "flip-then-enter-spam": ("ready", [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("ready", "unavailable")] + [x for _ in range(5) for x in (("key", E), ("wait", 0.05))] + [("wait", 0.8)]),
    "ready-again-r-then-enter-at-once": ("unavailable", [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("key", E), ("wait", 0.5), ("ready", "ready"), ("key", b"r\r"), ("wait", 0.8)]),
    "flapping-r-with-enters": ("unavailable", [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("key", E), ("wait", 0.5)] + [x for i in range(6) for x in (("ready", "ready" if i % 2 == 0 else "unavailable"), ("key", b"r"), ("wait", 0.1), ("key", E), ("wait", 0.1))] + [("wait", 0.8)]),
    "r-returns-ready-review-again-flip-unavailable": ("unavailable", [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("key", E), ("wait", 0.5), ("ready", "ready"), ("key", b"r"), ("wait", 0.9),
                                                                      *OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("ready", "unavailable"), ("key", E), ("wait", 0.8)]),
}


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
@pytest.mark.parametrize("case", sorted(_FLIP_CASES))
def test_pty_boundary_unavailable_never_starts_whatever_the_key_order(tmp_path, case):
    ready, script = _FLIP_CASES[case]
    assert _pty_run(tmp_path, _make_repo(tmp_path), script, (30, 100), ready=ready) == 0


@pytest.mark.skipif(not hasattr(pty, "fork"), reason="needs pty")
def test_pty_negative_control_ready_boundary_starts_once_and_recovers_after_r(tmp_path):
    """Controls for the cases above: ready = 1 start after the gate; unavailable then ready + r + a fresh review also = exactly 1."""
    assert _pty_run(tmp_path, _make_repo(tmp_path), [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("key", E), ("wait", 0.8)], (30, 100), ready="ready") == 1
    again = tmp_path / "again"
    again.mkdir()
    recover = [*OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("key", E), ("wait", 0.5), ("ready", "ready"), ("key", b"r"), ("wait", 0.9),
               *OPEN_CLAIM_C3, ("wait", 0.9), *_TO_END, ("key", E), ("wait", 0.8)]
    assert _pty_run(again, _make_repo(again), recover, (30, 100), ready="unavailable") == 1
