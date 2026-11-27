import json
import os
import subprocess
from pathlib import Path

from hlith.operator.state import LocalState
from hlith.operator import store
from hlith.tui import launch


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _write_engine_run(runs_root: Path, run_id: str, source: Path) -> Path:
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "meta.json").write_text(json.dumps({
        "run_id": run_id,
        "started": 1.0,
        "pid": os.getpid(),
        "pid_starttime": launch._starttime(os.getpid()),
        "source_repo": str(source.resolve()),
    }))
    return run_dir


def test_start_creates_nothing_and_history_lists_the_runs_check_records(tmp_path, monkeypatch):
    """Was: start() bound the spawned engine's HLITH_STATE_DIR to the launch record's root. Review-only (product.REVIEW_ONLY): start() spawns
    nothing and creates no launch folder. Runs are recorded by `hlith check` (a launch-* folder linking the engine's run-*), and History must
    still list them, list an unlinked engine run, and refuse a hostile cross-repository link."""
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q", "-b", "main")
    (source / "module.py").write_text("value = 1\n")
    _git(source, "add", "module.py")
    _git(source, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base")

    ui_state = tmp_path / "ui-state"
    other_engine_state = tmp_path / "other-engine-state"
    monkeypatch.setenv("HLITH_UI_STATE", str(ui_state))
    monkeypatch.setenv("HLITH_STATE_DIR", str(other_engine_state))
    plan = launch.plan(source, worker_cmd="true", state=ui_state)
    identity = LocalState().stable_repo_identity(source)
    spawned = []
    with monkeypatch.context() as during_start:  # scoped: the History listing below runs git through the same subprocess module
        during_start.setattr(launch.subprocess, "Popen", lambda *a, **k: spawned.append(a) or (_ for _ in ()).throw(AssertionError("start must not spawn")))
        meta = launch.start(plan)
    assert meta["state"] == launch.UNAVAILABLE_STATE and "hlith check" in meta["reason"]
    assert spawned == [] and not plan.run_dir.exists() and not other_engine_state.exists()

    # A linked record: a launch-* folder whose engine-run.json names the engine run-* beside it (the shape the store validates; `hlith check`
    # writes the link and the run-*, start used to write this meta.json). The listing below is unchanged from the original test.
    runs_root = launch._api(ui_state).state.namespace(identity, "runs")  # created as start created it (store modes), never a bare mkdir
    run_dir = _write_engine_run(runs_root, "run-0123456789ab", source)
    plan.run_dir.mkdir(parents=True)
    (plan.run_dir / "meta.json").write_text(json.dumps({
        "run_id": plan.run_dir.name,
        "started": 1.0,
        "pid": os.getpid(),
        "pid_starttime": launch._starttime(os.getpid()),
        "source_repo": str(source.resolve()),
    }))
    (plan.run_dir / "engine-run.json").write_text(json.dumps({"run_id": run_dir.name, "run_dir": str(run_dir)}))
    observed = {"runs_root": runs_root, "run_dir": run_dir}
    assert observed["runs_root"] == plan.run_dir.parent
    assert store.engine_run_dir(plan.run_dir) == observed["run_dir"]

    # The real layout has a launch-* record beside the engine's linked run-* record.
    rows = launch.runs_for(source, ui_state)
    assert [Path(row["run_dir"]).name for row in rows] == [plan.run_dir.name]

    # An unlinked engine run is still an independently visible run.
    standalone = _write_engine_run(observed["runs_root"], "run-aabbccddeeff", source)
    rows = launch.runs_for(source, ui_state)
    assert {Path(row["run_dir"]).name for row in rows} == {plan.run_dir.name, standalone.name}

    # A hostile launch link to a same-named run in another repository is not authority to hide this local run.
    other_runs = tmp_path / "other-repository" / "runs"
    foreign = _write_engine_run(other_runs, standalone.name, source)
    hostile_launch = observed["runs_root"] / "launch-deadbeef0000"
    hostile_launch.mkdir()
    (hostile_launch / "meta.json").write_text(json.dumps({
        "run_id": hostile_launch.name,
        "started": 2.0,
        "pid": os.getpid(),
        "pid_starttime": launch._starttime(os.getpid()),
        "source_repo": str(source.resolve()),
    }))
    (hostile_launch / "engine-run.json").write_text(json.dumps({"run_id": foreign.name, "run_dir": str(foreign)}))
    assert store.engine_run_dir(hostile_launch) is None
    rows = launch.runs_for(source, ui_state)
    assert {Path(row["run_dir"]).name for row in rows} == {
        plan.run_dir.name, standalone.name, hostile_launch.name,
    }
