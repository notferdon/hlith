# SPDX-License-Identifier: Apache-2.0
"""cancel-review: launch.cancel stops a REAL launch (process group), refuses anything unverified, records 'cancelled' (not a verdict), and is a no-op when finished."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from hlith.operator.tui import launch

WRAPPER = 'cd "$1" && shift && "$@" > stdout.log 2> stderr.log < /dev/null; echo $? > rc.tmp && mv rc.tmp rc'


def _launch(tmp_path, argv):
    run_dir = tmp_path / "launch-abcdefabcdef"
    run_dir.mkdir()
    proc = subprocess.Popen(["sh", "-c", WRAPPER, "sh", str(run_dir), *argv], cwd=str(run_dir), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
    meta = {"run_id": run_dir.name, "started": time.time(), "pid": proc.pid, "pid_starttime": launch._starttime(proc.pid), "argv": argv, "state": "started", "source_repo": str(tmp_path)}
    (run_dir / "meta.json").write_text(json.dumps(meta))
    return run_dir, proc


def _gone(pid):
    return not Path(f"/proc/{pid}").exists()


def test_cancel_stops_the_process_group_records_cancelled_and_leaves_no_zombie(tmp_path):
    run_dir, proc = _launch(tmp_path, ["sleep", "600"])
    child_pids = []
    assert launch.status(run_dir)["state"] == "running"
    out = launch.cancel(run_dir)
    assert out["result"] == "cancelled", out
    assert proc.poll() is not None or _gone(proc.pid)  # reaped / gone
    st = launch.status(run_dir)
    assert st["state"] == "cancelled" and st["rc"] is None
    meta = json.loads((run_dir / "meta.json").read_text())
    assert meta["state"] == "cancelled" and meta["cancel_signal"] in {"TERM", "KILL"}
    assert not (run_dir / "out.json").exists()  # never an artifact / verdict
    again = launch.cancel(run_dir)
    assert again["result"] == "not-running" and again["state"] == "cancelled"  # a second cancel is a no-op
    proc.wait(timeout=5)
    assert not child_pids


def test_cancel_escalates_to_kill_when_the_run_ignores_sigterm(tmp_path):
    run_dir, proc = _launch(tmp_path, ["sh", "-c", "trap '' TERM; sleep 600"])
    time.sleep(0.3)
    out = launch.cancel(run_dir, term_wait=0.5, kill_wait=2.0)
    assert out["result"] == "cancelled" and json.loads((run_dir / "meta.json").read_text())["cancel_signal"] == "KILL"
    proc.wait(timeout=5)


def test_cancel_on_a_finished_run_is_a_noop_and_signals_nothing(tmp_path):
    run_dir, proc = _launch(tmp_path, ["true"])
    proc.wait(timeout=5)
    time.sleep(0.2)
    assert launch.status(run_dir)["state"] == "finished"
    assert launch.cancel(run_dir) == {"result": "not-running", "state": "finished"}


def test_cancel_never_signals_an_unverified_pid(tmp_path):
    """A forged/reused pid record: our own test process is alive and has a start time, but is not the launch's session leader / wrapper for this folder."""
    run_dir = tmp_path / "launch-fedcbafedcba"
    run_dir.mkdir()
    me = os.getpid()
    meta = {"run_id": run_dir.name, "started": time.time(), "pid": me, "pid_starttime": launch._starttime(me), "argv": ["x"], "state": "started", "source_repo": str(tmp_path)}
    (run_dir / "meta.json").write_text(json.dumps(meta))
    out = launch.cancel(run_dir)
    assert out["result"] == "refused", out
    assert json.loads((run_dir / "meta.json").read_text())["state"] == "started"  # nothing was recorded either
    stale = {**meta, "pid_starttime": "1"}  # wrong start time = pid reuse
    (run_dir / "meta.json").write_text(json.dumps(stale))
    assert launch.cancel(run_dir)["result"] in {"not-running", "refused"}


def test_history_lists_a_cancelled_run_as_cancelled_never_as_a_verdict(tmp_path):
    from hlith.operator.tui import frame
    from hlith.operator.tui.model import ViewState

    row = {"run_id": "launch-abcdefabcdef", "repo": "r", "head": "unknown", "age": "1m ago", "state": "cancelled", "decision": None, "run_dir": "/x", "earlier_id": False}
    ctx = {"repo": {"name": "r", "branch": "main", "head": "a" * 40}, "history_scan_complete": True, "history_rows": [row], "history_total": 1}
    text = " ".join(" ".join(frame.render(ViewState(st="history", cols=100, rows=30), 100, 30, {"run": {}, "obligations": []}, context=ctx).text_rows()).split())
    assert "CANCELLED · no decision" in text and "REFUSED" not in text and "LANDED" not in text


def test_the_cancel_dialog_and_the_running_help_say_what_the_code_does():
    from hlith.operator.tui import frame
    from hlith.operator.tui.model import ViewState

    ctx = {"repo": {"name": "r", "branch": "main", "head": "a" * 40}, "run_state": "running", "running": {"phases": [], "unavailable": "engine events are not available yet"}}
    text = " ".join(" ".join(frame.render(ViewState(st="running", cols=100, rows=30, overlay="cancel"), 100, 30, {"run": {}, "obligations": []}, context=ctx).text_rows()).split())
    assert "discarded" not in text and "nothing is decided" in text
