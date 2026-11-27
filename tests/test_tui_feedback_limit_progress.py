"""case (8aa64410), design review's merge condition: L5 named limits are emitted as PROGRESS {"feedback_limit": ...}. PROGRESS is also the
channel the TUI live view reads as "now checking i of n", so a limit-only event must render nothing there and must never replace a
real progress row. It must not become a feedback PROBLEM either: that is the "FEEDBACK NOT RECORDED" text this change removes."""
import json
import os
import time
from datetime import datetime, timezone

import pytest

from hlith.operator import store
from hlith.operator.tui import launch

LIMIT = {"feedback_limit": "requests.utils.dotted_netmask: 1 probe input(s) reached the probe memory limit (RLIMIT_AS 2 GiB): UNEXPLORED"}


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
    (real / "meta.json").write_text(json.dumps({"run_id": "run-0123456789ab", "started": time.time(), "pid": os.getpid(),
                                                "pid_starttime": _starttime(os.getpid())}))
    launch._LIVE_CACHE.clear()

    def write(*events):
        with open(real / "events.v2.jsonl", "a") as fh:
            for seq, (kind, phase, detail, off) in enumerate(events, start=1):
                fh.write(json.dumps({"run_id": "run-0123456789ab", "seq": seq, "kind": kind, "phase": phase, "ts": _ts(off),
                                     "detail": detail}) + "\n")
    return launch_dir, real, write


def _rows(live):
    return dict(live.get("observed") or [])


def test_a_feedback_limit_only_progress_event_renders_nothing_in_the_live_view(run):
    launch_dir, _real, write = run
    write(("phase_started", "feedback", {}, -10), ("progress", "feedback", LIMIT, -5))
    rows = _rows(launch.live(launch_dir))
    assert "now checking" not in rows, rows
    assert not any("UNEXPLORED" in str(v) or "memory limit" in str(v) for v in rows.values()), rows


@pytest.mark.parametrize("limit_phase", ["obligation", "feedback"])
def test_a_feedback_limit_event_does_not_replace_a_real_progress_row(run, limit_phase):
    launch_dir, _real, write = run
    write(("phase_started", "obligation", {}, -30), ("progress", "obligation", {"target": "m.f", "i": 3, "n": 16}, -20),
          ("progress", limit_phase, LIMIT, -5))
    assert _rows(launch.live(launch_dir))["now checking"].startswith("3 of 16 · m.f")


def test_a_feedback_limit_is_not_a_feedback_problem_but_a_feedback_error_still_is(run):
    _launch_dir, real, write = run
    write(("phase_started", "feedback", {}, -10), ("progress", "feedback", LIMIT, -5))
    assert store.feedback_problems(real) == []
    write(("progress", "feedback", {"feedback_error": "feedback recording failed: OSError: read-only"}, -1))  # negative control
    assert store.feedback_problems(real) == ["feedback recording failed: OSError: read-only"]
