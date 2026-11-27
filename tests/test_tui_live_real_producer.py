"""TUI behavior: producer -> file -> TUI consumer, with review's REAL producer code (pipeline._EventLog + _emit_obligation_progress) and the REAL writer (store.append_event):
the byte format the engine actually writes is what launch.live reads. The L3 verify loop that calls progress() (review) is NOT part of this test: here progress() is called by the test."""
import json
import os
import time
from pathlib import Path

from hlith.contract.events import EventKind, Phase
from hlith.operator import pipeline, store
from hlith.operator.tui import launch


def _starttime(pid):
    return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[19]


def test_the_real_producer_and_writer_are_read_by_the_live_consumer(tmp_path):
    runs = tmp_path / "runs"
    launch_dir, rd = runs / "launch-aaaaaaaaaaaa", runs / "run-bbbbbbbbbbbb"
    launch_dir.mkdir(parents=True)
    rd.mkdir()
    (launch_dir / "engine-run.json").write_text(json.dumps({"run_id": "run-bbbbbbbbbbbb", "run_dir": str(rd)}))
    (rd / "meta.json").write_text(json.dumps({"run_id": "run-bbbbbbbbbbbb", "started": time.time(), "pid": os.getpid(), "pid_starttime": _starttime(os.getpid())}))
    launch._LIVE_CACHE.clear()
    log = pipeline._EventLog("run-bbbbbbbbbbbb", lambda ev: store.append_event(rd, ev))
    log.emit(EventKind.PHASE_STARTED, Phase.OBLIGATION, {})
    pipeline._emit_obligation_progress(log, "pkg.mod.func", 3, 16)
    live = launch.live(launch_dir)
    rows = dict(live["observed"])
    assert rows["now checking"].startswith("3 of 16 · pkg.mod.func"), live
    # a malformed call from the verifier (bad indices) emits nothing and cannot change what is shown
    pipeline._emit_obligation_progress(log, "other", 0, 5)
    pipeline._emit_obligation_progress(log, "other", True, 5)
    assert dict(launch.live(launch_dir)["observed"])["now checking"].startswith("3 of 16 · pkg.mod.func")
    log.emit(EventKind.PHASE_FINISHED, Phase.OBLIGATION, {})
    assert "now checking" not in dict(launch.live(launch_dir).get("observed") or [])
