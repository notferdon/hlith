"""History must show the verdict of a run recorded by `hlith check` (the only way Hlith Review records a run).

`hlith check` rehearses in process (operator/check.py ``_rehearse_inline``): its LAUNCH directory holds cmd.txt, engine-run.json, rc and
logs but no out.json, and the engine's own run directory ``run-<12 hex>`` holds meta.json, rc, receipt.json and out.json. History lists
the engine run directory, so the TUI has to read that directory's own artifact, bound to its own receipt. Observed on the installed
07135b3d wheel (2026-11-27 walk): every such run was listed as "FINISHED · no artifact" and opened as ARTIFACT UNAVAILABLE."""

from __future__ import annotations
import pytest

import json
import os
import subprocess
import time
from pathlib import Path

from hlith.contract.runs import LandingTarget, RunMode, RunReceipt
from hlith.operator import store
from hlith.operator.origin import InputOrigin
from hlith.operator.state import LocalState
from hlith.operator.tui import frame, launch

ROOT = Path(__file__).resolve().parents[1]
REFUSED = ROOT / "docs" / "evidence" / "acceptance" / "R1" / "4-regression-again.json"
RUN_ID = "run-c109261efa6f"


EVIDENCE = Path(__file__).resolve().parent.parent / "docs" / "evidence"
pytestmark = pytest.mark.skipif(not EVIDENCE.is_dir(), reason="source-only evidence fixture is not part of the public source snapshot")

def _recorded_by_check(runs: Path, *, run_id: str = RUN_ID, receipt_id: str | None = None, art_id: str | None = None) -> Path:
    """The two directories `hlith check` leaves behind (field-for-field the 07135b3d layout)."""
    launch_dir, run_dir = runs / "launch-c0712d5f5a75", runs / run_id
    launch_dir.mkdir(parents=True)
    run_dir.mkdir()
    (launch_dir / "cmd.txt").write_text("in-process check rehearsal: clone=/x/clone patch=/x/change.patch manifest=/x/m.json\n")
    (launch_dir / store.LINK).write_text(json.dumps({"run_id": run_id, "run_dir": str(run_dir)}) + "\n")
    (launch_dir / "rc").write_text("10\n")
    (run_dir / "meta.json").write_text(json.dumps({"run_id": run_id, "started": time.time() - 30, "pid": os.getpid(),
                                                   "pid_starttime": "1", "source_repo": "/x/repo"}))
    (run_dir / "rc").write_text("10\n")
    receipt = RunReceipt(receipt_id or run_id, "inv-e38cbe4b7a59", None, RunMode.HEADLESS, LandingTarget.REHEARSAL)
    store.write_receipt(run_dir, receipt, InputOrigin.SUPPLIED_PATCH, "repo-4d1d19810e683a4946e63e69", "/x/repo")
    art = json.loads(REFUSED.read_text())
    art["run"]["run_id"] = art_id or run_id
    (run_dir / store.ARTIFACT).write_text(json.dumps(art))
    return run_dir


def test_engine_run_dir_recorded_by_check_yields_its_own_artifact(tmp_path):
    run_dir = _recorded_by_check(tmp_path / "runs")
    rec = launch.result(run_dir)
    assert rec is not None and rec.usable, rec
    assert rec.art["run"]["run_id"] == RUN_ID
    assert frame._decision(rec.art)[0].startswith("REFUSED")


def test_history_row_for_check_run_names_the_recorded_decision(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-C", str(repo), "-c", "user.name=Hlith Test", "-c", "user.email=test@example.invalid"]
    subprocess.run([*git, "init", "-q", "-b", "main"], check=True)
    (repo / "a.txt").write_text("a\n")
    subprocess.run([*git, "add", "a.txt"], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "base"], check=True)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))  # the UI's engine store, as `hlith ui` resolves it
    runs = state / "repositories" / LocalState(state).stable_repo_identity(repo) / "runs"
    _recorded_by_check(runs)
    rows = launch.run_rows_with_summary(state, current_repo=repo)[0]
    mine = [r for r in rows if r["run_id"] == RUN_ID]
    assert len(mine) == 1, rows
    assert (mine[0]["decision"] or "").startswith("REFUSED"), mine[0]
    assert frame.history_state_text(mine[0]).startswith("FINISHED · REFUSED")


def test_receipt_for_another_run_is_not_accepted(tmp_path):
    run_dir = _recorded_by_check(tmp_path / "runs", receipt_id="run-000000000000")
    assert launch.result(run_dir) is None


def test_artifact_for_another_run_is_shown_as_mismatch_not_trusted(tmp_path):
    run_dir = _recorded_by_check(tmp_path / "runs", art_id="run-ffffffffffff")
    rec = launch.result(run_dir)
    assert rec is not None and rec.status == "id-mismatch" and not rec.usable


def test_symlinked_artifact_or_receipt_is_refused(tmp_path):
    a = _recorded_by_check(tmp_path / "a")
    real = tmp_path / "elsewhere.json"
    (a / store.ARTIFACT).rename(real)
    (a / store.ARTIFACT).symlink_to(real)
    assert launch.result(a) is None
    b = _recorded_by_check(tmp_path / "b")
    real_r = tmp_path / "receipt-elsewhere.json"
    (b / store.RECEIPT).rename(real_r)
    (b / store.RECEIPT).symlink_to(real_r)
    assert launch.result(b) is None


def test_directory_without_receipt_or_link_yields_nothing(tmp_path):
    run_dir = _recorded_by_check(tmp_path / "runs")
    (run_dir / store.RECEIPT).unlink()
    assert launch.result(run_dir) is None


def test_non_engine_named_directory_is_not_read_as_engine_run(tmp_path):
    run_dir = _recorded_by_check(tmp_path / "runs")
    other = run_dir.with_name("launch-aaaaaaaaaaaa")
    run_dir.rename(other)
    assert launch.result(other) is None
