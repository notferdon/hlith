"""The screens in a REAL pty (stdlib) against the real example artifacts, at several terminal sizes."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))  # tests/ is not a package: import the helper from this directory (works under bare `pytest`)
from _tui_pty import run_pty, strip  # noqa: E402

EX = Path(__file__).resolve().parent.parent / "docs" / "evidence" / "examples"
ARGV = [sys.executable, "-m", "hlith.tui"]
DOWN = "\x1bOB"


EVIDENCE = Path(__file__).resolve().parent.parent / "docs" / "evidence"
pytestmark = pytest.mark.skipif(not EVIDENCE.is_dir(), reason="source-only evidence fixture is not part of the public source snapshot")

@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
@pytest.mark.parametrize("cols", [60, 80, 120])
def test_open_traverse_and_quit_in_a_pty(cols, tmp_path):
    f = tmp_path / "fr.txt"
    rc, raw, _ = run_pty([*ARGV, str(EX)], keys=["w", "d", "e", "G", "h", "?", "x", "q"], rows=30, cols=cols, env={"HLITH_UI_FRAMES": str(f)})
    t = f.read_text()
    assert rc == 0
    assert "hlith" in t and "REFUSED" in t and "refuted" in t                   # decision from the newest record (the refusal after the fix)
    assert "o='é'" in t and "pre -> return 1" in t                              # the witness view
    assert "o = o.encode" in t                                                  # the diff view
    assert "GATE CONDITIONS" in t and "SCHEMA CHECK" in t                       # the evidence view
    assert "HISTORY" in t and "run_" in t                                       # the history view lists the records
    assert "No key lands, approves, or re-runs" in t                            # keys overlay


@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_a_historic_false_admission_keeps_its_label(tmp_path):
    f = tmp_path / "fr.txt"
    rc, raw, _ = run_pty([*ARGV, str(EX / "c-missed.json")], keys=["q"], rows=30, cols=100, env={"HLITH_UI_FRAMES": str(f)})
    t = " ".join(f.read_text().split())
    assert rc == 0 and "HISTORIC FALSE ADMISSION" in t and "LANDED" in t


@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_real_feedback_chain_is_visible_without_scrolling_in_a_pty(tmp_path):
    artifact = Path(__file__).resolve().parent.parent / "docs" / "evidence" / "acceptance" / "R1" / "4-regression-again.json"
    rec = json.loads(artifact.read_text())
    loaded = rec["feedback"]["loaded_feedback_ids"]
    frames = tmp_path / "feedback-frames.txt"
    rc, _raw, _marks = run_pty([*ARGV, str(artifact)], keys=["q"], rows=44, cols=120,
                               env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src"), "HLITH_UI_FRAMES": str(frames)})
    visible = frames.read_text()
    assert rc == 0 and len(loaded) > 0
    assert "FEEDBACK LOADED" in visible
    assert all(feedback_id in visible for feedback_id in loaded)


@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_malformed_and_missing_in_a_pty(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{oops")
    f = tmp_path / "f1.txt"
    rc, raw, _ = run_pty([*ARGV, str(bad)], keys=["q"], rows=24, cols=80, env={"HLITH_UI_FRAMES": str(f)})
    t = f.read_text()
    assert rc == 0 and "UNREADABLE" in t and "not shown as a decision" in t and "not JSON" in t
    g = tmp_path / "f2.txt"
    rc, raw, _ = run_pty([*ARGV, str(tmp_path / "gone.json")], keys=["q"], rows=24, cols=80, env={"HLITH_UI_FRAMES": str(g)})
    assert rc == 0 and "UNREADABLE" in g.read_text() and "no such file" in g.read_text()


@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_non_tty_fallback_prints_text_and_exits_zero():
    import subprocess
    p = subprocess.run([*ARGV, str(EX / "b-refusal.json")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and "REFUSED" in p.stdout and "u:p@example.com" in p.stdout and "\x1b" not in p.stdout
    q = subprocess.run([*ARGV, "/nonexistent-dir-x/zz.json"], capture_output=True, text=True, timeout=60)
    assert "NO RECORD" in q.stdout
    e = subprocess.run([*ARGV], capture_output=True, text=True, timeout=60, cwd="/",
                       env={"HLITH_UI_STATE": "/nonexistent-state-x", "PATH": "/usr/bin:/bin", "PYTHONPATH": str(Path(__file__).parent.parent / "src")})
    assert e.returncode == 2 and "not a git repository" in e.stderr  # no arguments outside a repository: say so (not a crash)


@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_too_small_terminal_says_so():
    rc, raw, _ = run_pty([*ARGV, str(EX)], keys=["q"], rows=6, cols=30)
    assert "too small" in strip(raw) and rc == 0


@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_mono_mode_has_no_colour_but_every_status_has_a_word():
    import tempfile
    fr = Path(tempfile.mkdtemp()) / "fr.txt"
    rc, raw, _ = run_pty([*ARGV, str(EX / "b-refusal.json")], keys=["q"], rows=30, cols=100, env={"NO_COLOR": "1", "HLITH_UI_FRAMES": str(fr)})
    s = raw.decode("utf-8", "replace")
    import re
    t = fr.read_text()
    assert rc == 0 and not re.search(r"\x1b\[[0-9;]*3[0-7]m|\x1b\[[0-9;]*4[0-7]m|\x1b\[38;5|\x1b\[48;5", s) and "REFUSED" in t and "refuted" in t


@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_hlith_ui_entry_in_the_cli_and_other_commands_unchanged():
    import subprocess
    p = subprocess.run([sys.executable, "-m", "hlith.cli", "ui", "--plain", str(EX / "b-refusal.json")], capture_output=True, text=True, timeout=60)
    assert p.returncode == 0 and "REFUSED" in p.stdout and "-- Witness --" in p.stdout
    h = subprocess.run([sys.executable, "-m", "hlith.cli", "run", "--help"], capture_output=True, text=True, timeout=60)
    assert h.returncode == 0 and "--patch" in h.stdout
    bad = subprocess.run([sys.executable, "-m", "hlith.cli", "nonsense"], capture_output=True, text=True, timeout=60)
    assert bad.returncode == 2
