# SPDX-License-Identifier: Apache-2.0
"""review (G2), design review trace e1resume3, red-first on bd21e751: `resume THREAD --redo-inflight` of a thread whose run had already RECORDED a
decision (refused, agent-runtime-boundary) re-called the proposer and the gate LANDED in the target, while the kept out.json still said
refused (rc 0 vs artifact refused/4). Required: such a resume is refused BEFORE the pipeline runs (no proposer call, no target write),
naming the decided run. A thread whose run has no recorded decision (e.g. parked at its effect interrupt) still resumes (control)."""

from __future__ import annotations

import json
import os
import subprocess
from types import SimpleNamespace

from hlith.contract.errors import EXIT_BOUNDARY
from hlith.contract.identities import ThreadId
from hlith.contract.runs import LandingTarget, RunMode
from hlith.operator import coordinator
from hlith.operator.state import LocalState

THREAD = "thread-0123456789abcdef"
RUN = "run-aaaaaaaaaaaa"


def _setup(tmp_path, decided: bool):
    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=a@b", "-c", "user.name=n", "commit", "-q", "--allow-empty", "-m", "x"],
                   check=True)
    tstore = tmp_path / "threads"
    for sub in ("ckpt", "driver", "inputs", "stage", "channel"):  # the private layout every persisted thread has
        (tstore / THREAD / sub).mkdir(parents=True, mode=0o700, exist_ok=True)
    for d in (tstore, tstore / THREAD):
        os.chmod(d, 0o700)
    (tstore / THREAD / "meta.json").write_text(json.dumps({"thread_id": THREAD, "run_id": RUN, "target_path": str(repo)}))
    co = coordinator.Coordinator(LocalState(tmp_path / "st"))
    run_dir = co.state.namespace(co.state.stable_repo_identity(repo), "runs") / RUN
    run_dir.mkdir(parents=True)
    if decided:
        (run_dir / "out.json").write_text(json.dumps({"outcome": "refused", "exit_status": 4}))
    req = coordinator.RunRequest(repo=repo, mode=RunMode.STANDALONE, landing_target=LandingTarget.ORIGINAL,
                                 resume_thread_id=ThreadId(THREAD))
    return co, req, SimpleNamespace(agent_api=SimpleNamespace(thread_store=tstore), gate_api=None), run_dir


def test_a_resume_of_a_thread_whose_run_already_decided_is_refused_before_anything_runs(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(coordinator, "run_pipeline", lambda *a, **k: calls.append(1) or (_ for _ in ()).throw(AssertionError("ran")))
    co, req, caps, run_dir = _setup(tmp_path, decided=True)
    out = co.execute(req, caps)
    assert calls == [], "the pipeline (proposer + gate) ran for an already-decided run"
    assert out.exit_status == EXIT_BOUNDARY and any(RUN in p and "already recorded its decision" in p for p in out.problems), out
    assert json.loads((run_dir / "out.json").read_text()) == {"outcome": "refused", "exit_status": 4}


def test_a_resume_of_a_thread_without_a_recorded_decision_still_reaches_the_pipeline(tmp_path, monkeypatch):
    calls = []

    def tripwire(*a, **k):
        calls.append(1)
        raise RuntimeError("reached the pipeline")

    monkeypatch.setattr(coordinator, "run_pipeline", tripwire)
    co, req, caps, _ = _setup(tmp_path, decided=False)
    co.execute(req, caps)
    assert calls == [1]
