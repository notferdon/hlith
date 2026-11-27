"""TUI behavior (operator UX): native progress during LONG checks from the FROZEN event contract, red-first.
A 1256 s obligation phase used to show only 'obligation running 901s' and 'event progress is not available': a live check was indistinguishable from a hung one.
The TUI now consumes (never writes) the v2 events: a PROGRESS event {target, i, n} names what is being checked, the age of the last event and the engine process liveness
are always shown. Nothing is invented: absent events stay explicit."""
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from hlith.operator.tui import frame, launch


def _ts(offset=0.0):
    return datetime.fromtimestamp(time.time() + offset, timezone.utc).isoformat()


def _starttime(pid):
    return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[19]


@pytest.fixture()
def run(tmp_path):
    runs = tmp_path / "runs"
    launch_dir = runs / "launch-aaaaaaaaaaaa"
    real = runs / "run-0123456789ab"
    launch_dir.mkdir(parents=True)
    real.mkdir()
    (launch_dir / "engine-run.json").write_text(json.dumps({"run_id": "run-0123456789ab", "run_dir": str(real)}))
    (real / "meta.json").write_text(json.dumps({"run_id": "run-0123456789ab", "started": time.time(), "pid": os.getpid(), "pid_starttime": _starttime(os.getpid())}))
    launch._LIVE_CACHE.clear()

    def write(*events):
        with open(real / "events.v2.jsonl", "a") as fh:
            for seq, (kind, phase, detail, off) in enumerate(events, start=1):
                fh.write(json.dumps({"run_id": "run-0123456789ab", "seq": seq, "kind": kind, "phase": phase, "ts": _ts(off), "detail": detail}) + "\n")
    return launch_dir, real, write


def _rows(live):
    return dict(live.get("observed") or [])


def test_a_progress_event_names_what_is_being_checked(run):
    launch_dir, _real, write = run
    write(("phase_started", "obligation", {}, -30), ("progress", "obligation", {"target": "bidict._orderedbidict.make_proxy_method", "i": 3, "n": 16}, -5))
    rows = _rows(launch.live(launch_dir))
    assert rows["now checking"].startswith("3 of 16 · bidict._orderedbidict.make_proxy_method")  # the count comes first so a narrow terminal cannot cut it


def test_progress_is_cleared_when_its_phase_finishes(run):
    launch_dir, _real, write = run
    write(("phase_started", "obligation", {}, -30), ("progress", "obligation", {"target": "m.f", "i": 1, "n": 2}, -20), ("phase_finished", "obligation", {}, -10))
    assert "now checking" not in _rows(launch.live(launch_dir))


def test_the_age_of_the_last_event_is_always_shown_while_running(run):
    launch_dir, _real, write = run
    write(("phase_started", "obligation", {}, -125))
    rows = _rows(launch.live(launch_dir))
    assert rows["last event"].startswith("2m 0") and "ago" in rows["last event"] and "obligation" in rows["last event"]


def test_engine_process_liveness_alive_dead_and_pid_reuse(run):
    launch_dir, real, write = run
    write(("phase_started", "obligation", {}, -3))
    assert _rows(launch.live(launch_dir))["engine process"].startswith("running")
    meta = json.loads((real / "meta.json").read_text())
    (real / "meta.json").write_text(json.dumps({**meta, "pid_starttime": "1"}))  # same pid, different start time: a REUSED pid is not our engine
    launch._LIVE_CACHE.clear()
    assert _rows(launch.live(launch_dir))["engine process"].startswith("not running")
    (real / "meta.json").write_text(json.dumps({**meta, "pid": 2 ** 22 + 12345}))
    launch._LIVE_CACHE.clear()
    assert _rows(launch.live(launch_dir))["engine process"].startswith("not running")


def test_hostile_progress_detail_is_bounded_and_cannot_carry_a_verdict(run):
    launch_dir, _real, write = run
    write(("phase_started", "obligation", {}, -3),
          ("progress", "obligation", {"target": "x\x1b[31mred\x07" + "a" * 500, "i": "NaN", "n": True, "verdict": "held", "outcome": "landed"}, -1))
    live = launch.live(launch_dir)
    assert "\x1b" not in json.dumps(live) and "\x07" not in json.dumps(live)
    row = _rows(live).get("now checking", "")
    assert "\x1b" not in row and len(row) <= 200 and "landed" not in row and "held" not in row


def test_no_events_stays_explicit_and_frame_renders_the_rows(run):
    launch_dir, _real, write = run
    write(("phase_started", "obligation", {}, -30), ("progress", "obligation", {"target": "m.f", "i": 2, "n": 5}, -2))
    live = launch.live(launch_dir)
    rows = frame._observed_rows(10, 100, {"running": live, "run_state": "running"})
    flat = " ".join("".join(c for c, _s in row) if isinstance(row, list) and row and isinstance(row[0], tuple) else str(row) for row in rows)
    assert "now checking" in flat or "m.f" in flat


def test_a_progress_event_with_only_feedback_limit_renders_nothing_and_keeps_the_real_row(run):
    """design review/review condition (8aa64410): PROGRESS carries {"feedback_limit": ...} (no target/i/n): it must not draw a row nor replace a real one."""
    launch_dir, _real, write = run
    write(("phase_started", "obligation", {}, -30), ("progress", "obligation", {"target": "m.f", "i": 2, "n": 5}, -20), ("progress", "obligation", {"feedback_limit": 3}, -10))
    rows = _rows(launch.live(launch_dir))
    assert rows["now checking"].startswith("2 of 5 · m.f")
    launch._LIVE_CACHE.clear()
    launch_dir2, real2 = launch_dir, _real
    (real2 / "events.v2.jsonl").unlink()
    write(("phase_started", "obligation", {}, -30), ("progress", "obligation", {"feedback_limit": 3}, -10))
    assert "now checking" not in _rows(launch.live(launch_dir2))


@pytest.mark.parametrize("partial", [{"i": 4}, {"n": 9}, {"i": 4, "n": 9}, {"i": "x", "n": None}])
def test_a_partial_progress_detail_without_a_target_never_replaces_a_real_row(run, partial):
    launch_dir, _real, write = run
    write(("phase_started", "obligation", {}, -30), ("progress", "obligation", {"target": "m.f", "i": 2, "n": 5}, -20), ("progress", "obligation", partial, -10))
    assert _rows(launch.live(launch_dir))["now checking"].startswith("2 of 5 · m.f")
