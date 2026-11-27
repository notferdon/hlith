"""RUNNING screen reads the engine's real event file; falls back to pid + elapsed; proven against a real engine run."""
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))  # tests/ is not a package (bare pytest)
from _tui_pty import run_pty  # noqa: E402

from hlith.contract.events import EventKind  # noqa: E402
from hlith.operator import store  # noqa: E402
from hlith.tui import launch  # noqa: E402


def _event_phase_measurements(recs):
    """Unique phase order and accumulated durations from the typed engine event stream."""
    order, started, seconds = [], {}, {}
    for event in recs:
        if event.phase is None:
            continue
        name = event.phase.value
        timestamp = datetime.fromisoformat(event.ts.replace("Z", "+00:00")).timestamp()
        if event.kind is EventKind.PHASE_STARTED:
            if name not in order:
                order.append(name)
            started[name] = timestamp
        elif event.kind is EventKind.PHASE_FINISHED and name in started:
            seconds[name] = seconds.get(name, 0.0) + max(0.0, timestamp - started.pop(name))
    return order, seconds


def _assert_phase_display_matches(shown, displayed_seconds, expected_order, event_seconds):
    assert shown == expected_order, f"display order {shown!r} != event order {expected_order!r}"
    assert set(displayed_seconds) == set(expected_order), (
        f"displayed phases {sorted(displayed_seconds)!r} != event phases {sorted(expected_order)!r}"
    )
    for name in expected_order:
        tolerance = 0.6 + 0.25 * event_seconds[name]
        assert abs(displayed_seconds[name] - event_seconds[name]) <= tolerance, (
            name, displayed_seconds[name], event_seconds[name], tolerance
        )


def _ev(path, rows):
    with open(path, "w") as f:
        for i, (ph, ev, t, extra) in enumerate(rows, 1):
            r = {"seq": i, "ts_mono": t, "ts_wall": 1.0, "run_id": "r", "phase": ph, "event": ev}
            if extra:
                r["extra"] = extra
            f.write(json.dumps(r) + "\n")


def test_phase_display_contract_rejects_mutated_order_and_duration():
    order = ["runtime", "effect", "obligation"]
    seconds = {"runtime": 0.0, "effect": 0.03, "obligation": 2.0}
    with pytest.raises(AssertionError, match="display order"):
        _assert_phase_display_matches(["effect", "runtime", "obligation"], seconds, order, seconds)
    wrong_duration = {**seconds, "obligation": 4.0}
    with pytest.raises(AssertionError, match="obligation"):
        _assert_phase_display_matches(order, wrong_duration, order, seconds)


def test_no_phase_is_shown_before_the_engine_entered_it(tmp_path):
    _ev(tmp_path / "events.jsonl", [("stage_and_worker", "start", 1.0, None)])
    assert [p["name"] for p in launch.live(tmp_path, now_mono=2.0)["phases"]] == ["stage_and_worker"]  # nothing speculative about what comes next


def test_plan_links_the_engine_run_and_passes_no_events_file(tmp_path):
    """Changed seam: the pipeline engine writes contract events into ITS OWN run directory (minted RunId); the launcher only passes
    --run-link inside the launch directory to learn where it is. No --events-out file is asked for any more."""
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "-C", str(r), "init", "-q"], check=True)
    pl = launch.plan(r, worker_cmd="x", state=tmp_path / "st")
    assert "--events-out" not in pl.argv and pl.argv[pl.argv.index("--run-link") + 1] == str(pl.run_dir / "engine-run.json")
    assert "--approve-deltas" not in pl.display()


@pytest.mark.real  # a real engine run through the real RUNNING screen (about 20 s)
def test_running_screen_phase_order_and_durations_match_the_events_file_and_the_artifact(tmp_path):
    def g(*a):
        subprocess.run(["git", "-C", str(work), "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True, capture_output=True)
    work = tmp_path / "proj"
    work.mkdir()
    g("init", "-q", "-b", "main")
    (work / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (work / "other.py").write_text("def mul(a, b):\n    return a * b\n")
    g("add", "-A")
    g("commit", "-q", "-m", "base")
    (work / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    st = tmp_path / "st"
    frames = tmp_path / "frames.txt"
    rc, raw, _ = run_pty([sys.executable, "-m", "hlith.tui"], keys=["n", "\n", "\n", "\n", "~wait:3", "~until:target :240", "~wait:1", "q"], rows=36, cols=90, cwd=str(work),
                         env={"HLITH_UI_STATE": str(st), "HLITH_UI_FRAMES": str(frames), "GIT_CEILING_DIRECTORIES": str(tmp_path)}, timeout=300)
    assert rc == 0
    launch_dirs = list(st.rglob("launch-*"))
    assert len(launch_dirs) == 1
    launch_dir = launch_dirs[0]
    assert not (st / "runs").exists()  # the former root-level path is not the current repository namespace
    run_dir = store.engine_run_dir(launch_dir)
    assert run_dir is not None and run_dir.is_dir()
    assert (launch_dir / "engine-run.json").is_file()
    assert (run_dir / "events.v2.jsonl").is_file()
    recs, problems = store.read_events(run_dir)
    assert recs and not problems
    art = json.loads((run_dir / "out.json").read_text())
    # The pipeline artifact has no per-phase timings; typed events.v2 provide the canonical order and durations.
    expected_order, event_seconds = _event_phase_measurements(recs)
    # what the screen displayed, in order of first appearance across the RUNNING frames
    text = frames.read_text()
    running = [f for f in text.split("=== frame") if "INVESTIGATING" in f and "PHASES" in f]
    assert running, "the in-progress screen never showed engine phases"
    shown, displayed_seconds = [], {}
    phase_row = re.compile(r"^\s*([a-z][a-z0-9_-]*)\s+(running|done)\s+([0-9.]+)s\s*$", re.M)
    for f in running:
        for m in phase_row.finditer(f):
            name = m.group(1)
            if name not in shown:
                shown.append(name)
            displayed_seconds[name] = float(m.group(3))
    _assert_phase_display_matches(shown, displayed_seconds, expected_order, event_seconds)
    assert art["outcome"] == "refused" and art["exit_status"] == 10
    assert recs[-1].kind is EventKind.ARTIFACT_WRITTEN
