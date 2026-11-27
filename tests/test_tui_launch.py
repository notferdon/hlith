"""Launch path: plan/command, disposable clone, detached lifecycle, a REAL engine run on a toy repo, and the pty flow."""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from hlith.tui import launch, model
sys.path.insert(0, str(Path(__file__).parent))  # tests/ is not a package: import the helper from this directory (works under bare `pytest`)
from _tui_pty import run_pty, strip  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


EVIDENCE = ROOT / "docs" / "evidence"


def _git(cwd, *a):
    return subprocess.run(["git", "-C", str(cwd), "-c", "user.name=t", "-c", "user.email=t@t", *a], capture_output=True, text=True, check=True).stdout


@pytest.fixture()
def toy(tmp_path):
    r = tmp_path / "src-repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    (r / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (r / "other.py").write_text("def mul(a, b):\n    return a * b\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    (r / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "swap.patch").write_text(_git(r, "diff"))
    (inputs / "swap.manifest.json").write_text(json.dumps({"paths": {"calc.py": ["modify"]}}))
    _git(r, "checkout", "-q", "calc.py")
    return r, inputs, tmp_path / "state"


def _wait(run_dir, timeout=180):
    t0 = time.time()
    while time.time() - t0 < timeout:
        st = launch.status(run_dir)
        if st["state"] != "running":
            return st
        time.sleep(0.3)
    raise AssertionError("run did not finish")


def test_plan_shows_the_exact_human_command_and_never_approves(toy):
    r, inputs, state = toy
    pair = launch.find_pairs([inputs])
    assert [(p.name, m.name) for p, m in pair] == [("swap.patch", "swap.manifest.json")]
    pl = launch.plan(r, patch=pair[0][0], manifest=pair[0][1], state=state, target_python="/x/python")
    # the ordinary journey runs the PIPELINE engine on a rehearsal clone; the engine mints the RunId (no --run-id), the launcher follows --run-link
    assert pl.argv[1:4] == ["-m", "hlith.operator.engine_cli", "run"] and pl.argv[pl.argv.index("--engine") + 1] == "pipeline"
    assert pl.argv[pl.argv.index("--repo") + 1] == str(pl.clone) and pl.clone == pl.run_dir / "clone"  # the engine gets the CLONE
    assert pl.argv[pl.argv.index("--source-repo") + 1] == str(r.resolve()) and "--run-id" not in pl.argv
    assert pl.argv[pl.argv.index("--run-link") + 1] == str(pl.run_dir / "engine-run.json")
    assert pl.argv[pl.argv.index("--surface-mode") + 1] == "companion" and pl.argv[pl.argv.index("--invocation-id") + 1] == launch._INVOCATION
    assert "--approve-deltas" not in pl.argv and "--approve-deltas" not in pl.display()
    assert pl.argv[pl.argv.index("--patch") + 1] == str((inputs / "swap.patch").resolve()) and "--manifest" in pl.argv
    assert pl.argv[pl.argv.index("--target-python") + 1] == "/x/python"
    w = launch.plan(r, worker_cmd="python edit.py", state=state)
    assert w.argv[w.argv.index("--worker-cmd") + 1] == "python edit.py" and "--patch" not in w.argv
    assert w.argv[w.argv.index("--surface-mode") + 1] == "standalone"
    with pytest.raises(ValueError):  # the engine mints the RunId: the UI cannot supply one
        launch.plan(r, worker_cmd="x", state=state, run_id="run-0123456789ab")
    with pytest.raises(ValueError):
        launch.plan(r, state=state)
    with pytest.raises(ValueError):
        launch.plan(r, patch=pair[0][0], worker_cmd="x", state=state)


@pytest.mark.skipif(not EVIDENCE.is_dir(), reason="source-only evidence fixture is not part of the public source snapshot")
def test_recorded_case_inputs_are_found_by_name():
    pairs = launch.find_pairs([ROOT / "docs" / "evidence" / "evidence-case-20261113"])
    assert ("op.patch", "op.manifest.json") in [(p.name, m.name if m else None) for p, m in pairs]


def _would_have_run(tmp_path):
    """An argv that leaves a file behind if anything ever executes it."""
    sentinel = tmp_path / "ran.txt"
    return sentinel, [sys.executable, "-c", f"open({str(sentinel)!r}, 'w').write('ran')"]


def test_start_is_unavailable_in_hlith_review_and_creates_no_clone_run_or_process(toy, tmp_path):
    """Review-only distribution (product.REVIEW_ONLY): the terminal screen starts no check. Was: a detached run went running -> finished on a
    disposable clone. Now: start() names the supported path (`hlith check`) and creates no launch folder, clone or process."""
    r, _inputs, state = toy
    before = _git(r, "status", "--porcelain=v1") + _git(r, "rev-parse", "HEAD")
    pl = launch.plan(r, worker_cmd="x", state=state)
    sentinel, pl.argv = _would_have_run(tmp_path)
    meta = launch.start(pl)
    assert meta["state"] == launch.UNAVAILABLE_STATE and meta["reason"] == launch.UNAVAILABLE_REASON and "hlith check" in meta["reason"]
    assert "pid" not in meta and not pl.run_dir.exists() and not pl.clone.exists()
    time.sleep(0.5)
    assert not sentinel.exists(), "nothing may execute"
    assert launch.status(pl.run_dir)["state"] == "unknown"  # no record of a run that never started
    assert _git(r, "status", "--porcelain=v1") + _git(r, "rev-parse", "HEAD") == before


def test_a_ui_that_exits_after_start_leaves_no_detached_run(toy, tmp_path):
    """Was: the detached run survived the UI's exit. Now: a UI process that calls start() and exits leaves nothing running and nothing on disk."""
    r, _i, state = toy
    code = (f"import sys, json; sys.path.insert(0, {str(ROOT / 'src')!r}); from hlith.tui import launch; "
            f"pl = launch.plan({str(r)!r}, worker_cmd='x', state={str(state)!r}); "
            "pl.argv = [sys.executable, '-c', 'import time; time.sleep(5)']; m = launch.start(pl); print(json.dumps([str(pl.run_dir), m['state'], m.get('pid')]))")
    run_dir, state_word, pid = json.loads(subprocess.run([sys.executable, "-c", code], check=True, timeout=60, capture_output=True, text=True).stdout.strip())
    assert state_word == launch.UNAVAILABLE_STATE and pid is None
    time.sleep(0.5)
    assert not Path(run_dir).exists()
    assert launch.status(Path(run_dir))["state"] == "unknown"


def test_a_start_that_never_happened_is_not_invented_as_lost_or_running(toy):
    """Was: a killed run read `lost` with no exit code. Now: there is no process to kill; the never-started plan is `unknown`, never running/lost/finished."""
    r, _i, state = toy
    pl = launch.plan(r, worker_cmd="x", state=state)
    pl.argv = [sys.executable, "-c", "import time; time.sleep(60)"]
    meta = launch.start(pl)
    assert "pid" not in meta and meta["state"] == launch.UNAVAILABLE_STATE
    st = launch.status(pl.run_dir)
    assert st["state"] == "unknown" and st["state"] not in ("running", "lost", "finished")


def test_unknown_run_dir(tmp_path):
    assert launch.status(tmp_path)["state"] == "unknown"


@pytest.mark.real  # runs the real engine (about 15 s): opt in with -m real; the full suite includes it
def test_real_engine_run_on_a_toy_repo_reads_back_the_recorded_decision(toy):
    r, inputs, state = toy
    p, m = launch.find_pairs([inputs])[0]
    pl = launch.plan(r, patch=p, manifest=m, state=state)
    launch.start(pl)
    st = _wait(pl.run_dir)
    rec = launch.result(pl.run_dir)
    assert st["state"] == "finished" and rec is not None and rec.usable
    label = model.decision(rec.art)[0]
    assert label.split()[0] in ("LANDED", "REFUSED") and rec.art["exit_status"] == st["rc"]  # the UI shows the artifact's own decision
    assert "calc.py" in rec.art["effect"]["touched_files"]
    assert "b + a" not in (r / "calc.py").read_text()  # the source repo was never touched


@pytest.mark.real  # real pty session that launches the real engine (about 30 s)
def test_pty_flow_choose_confirm_run_and_see_the_decision(toy):
    """The SHIPPED flow end to end on a small repository with the REAL engine: Offer -> Selection -> Claim -> command review to its END -> Run -> Verdict,
    asserting the decision words come from the recorded artifact and that the operator's own repository is byte-for-byte unchanged (tree hash)."""
    import hashlib

    r, inputs, state = toy
    (r / "calc.py").write_text("def add(a, b):\n    return b + a\n")  # the agent's edit, left UNCOMMITTED (the fixture restores calc.py)

    def tree_hash():
        h = hashlib.sha256()
        for p in sorted(r.rglob("*")):
            if ".git" in p.relative_to(r).parts or not p.is_file():
                continue
            h.update(str(p.relative_to(r)).encode() + b"\0" + hashlib.sha256(p.read_bytes()).digest())
        return h.hexdigest()

    before = tree_hash()
    head_before = _git(r, "rev-parse", "HEAD").strip()
    pgdn, esc = "\x1b[6~", "\x1b"
    keys = ["~wait:3", "\n", "~wait:1.5", "\n", "~wait:2", "c", "~wait:1", pgdn, "~wait:0.7", pgdn, "~wait:0.7", pgdn, "~wait:0.7", esc, "~wait:1.5", "\n",
            "~until:exit :240", "~wait:2", "q", "~wait:0.6", "\t", "~wait:0.4", "\n", "~wait:1.5"]
    frames_file = state.parent / "frames.txt"
    rc, raw, _ = run_pty([sys.executable, "-m", "hlith.operator.tui", "--repo", str(r), "--target-python", sys.executable], keys=keys, rows=36, cols=120,
                         env={"HLITH_UI_STATE": str(state), "HLITH_UI_FRAMES": str(frames_file)}, timeout=300)
    frames = frames_file.read_text()
    flat = " ".join(frames.replace("│", " ").split())
    assert "Review command" in flat and "EXACT COMMAND" in flat and "END OF COMMAND" in flat  # the command was reviewed on its own page
    assert "--artifact-out" in flat and "--approve-deltas" not in flat
    assert "CHECKING" in flat and "elapsed" in flat  # the Running screen was shown while the engine worked
    arts = sorted(state.glob("host/repositories/*/runs/launch-*/out.json"))  # the launch folder's artifact (the engine keeps its own run-* record beside it)
    assert len(arts) == 1, arts
    art = json.loads(arts[0].read_text())
    word = {"landed": "LANDED", "refused": "REFUSED"}[art["outcome"]]
    assert word in frames and f"exit {art['exit_status']}" in frames  # the decision on screen is the artifact's own
    assert rc == 0
    rows, *_ = launch.run_rows_with_summary(state, r)
    assert len(rows) == 1 and rows[0]["state"] == "finished", rows
    assert tree_hash() == before and _git(r, "rev-parse", "HEAD").strip() == head_before  # the operator's repository is untouched (the check ran on a clone)


@pytest.mark.skip(reason="SUPERSEDED by the current public contract; source-only coverage is in the full source repository")
def test_feedback_bridge_persists_from_refused_run_to_distinct_second_run(toy):
    from hlith import feedback
    r, inputs, state = toy
    # Run 1 (simulated finished run) writes a real FeedbackRecord in its disposable clone
    pl1 = launch.plan(r, worker_cmd="x", state=state)
    pl1.argv = [sys.executable, "-c", "print('run1')"]
    launch.start(pl1)
    assert _wait(pl1.run_dir)["rc"] == 0
    rec = feedback.pin_regression_counterexample(
        "run-1", "calc.add", [1, 2], {},
        expected={"kind": "return", "value_repr": "3"},
        observed={"kind": "return", "value_repr": "99"},
    )
    feedback.persist(pl1.clone, rec)
    assert not (r / ".hlith").exists()

    # Run 2 (distinct run on a fresh clone of the same source repo) must receive Run 1's feedback
    p, m = launch.find_pairs([inputs])[0]
    pl2 = launch.plan(r, patch=p, manifest=m, state=state)
    pl2.argv = [sys.executable, "-c", "print('run2')"]
    launch.start(pl2)
    assert _wait(pl2.run_dir)["rc"] == 0
    loaded = feedback.load_records(pl2.clone, None)
    assert [x.feedback_id for x in loaded] == [rec.feedback_id]
    assert not (r / ".hlith").exists()


