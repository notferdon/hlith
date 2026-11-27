"""Default resume of a LangGraph effect interrupt must re-enter the gate. It must not call the proposer again,
and it must not record an interrupted refusal in place of a verdict.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from hlith.agent.errors import RuntimeBoundary

sys.path.insert(0, str(Path(__file__).resolve().parent))
from effect_park import landlock_enosys, park_layer1_patch  # noqa: E402

from hlith.agent.checkpoint import describe_thread
from hlith.agent.supervisor import resume_captured_worker
from hlith.operator import engine_cli
from hlith.operator.host import agent_progress, captured_interrupts
from hlith.operator.tui import launch

M_PY = "def add_one(x: int) -> int:\n    return x + 1\n"
T_PY = "from m import add_one\n\n\ndef test_add_one():\n    assert add_one(1) == 2\n"


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "m.py").write_text(M_PY)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_m.py").write_text(T_PY)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo


def _park(repo, store, *, deltas=None, replacement="return x + 2"):
    (repo / "m.py").write_text(M_PY.replace("return x + 1", replacement))
    patch = subprocess.run(["git", "-C", str(repo), "diff"], check=True, capture_output=True).stdout
    subprocess.run(["git", "-C", str(repo), "checkout", "-q", "."], check=True, capture_output=True)
    run = park_layer1_patch(
        repo, store, patch,
        manifest_bytes=json.dumps({"paths": {"m.py": ["modify"]}, "deltas": deltas or []}).encode(),
    )
    thread = run.graph.thread_id
    interrupt = run.graph.interrupt_checkpoint_id
    run.graph.close()
    return thread, interrupt


def _run_meta(repo, store):
    return {"meta": {"clone": str(repo), "run_id": "launch", "argv": [
        "hlith", "run", "--engine", "pipeline", "--proposer-command", "/bin/true",
        "--thread-store", str(store),
    ]}}


def test_captured_effect_is_not_on_the_agent_progress_path_and_wrong_ids_do_not_judge(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    thread, interrupt = _park(repo, store)
    desc = describe_thread(thread, store)
    assert desc["kind"] == "effect-interrupt" and desc["captured_mac"] and desc["interrupt_checkpoint_id"] == interrupt
    assert agent_progress(_run_meta(repo, store)) == []
    found = captured_interrupts(_run_meta(repo, store))
    assert [row["thread_id"] for row in found] == [thread]
    assert found[0]["interrupt_checkpoint_id"] == interrupt and found[0]["kind"] == "effect-interrupt"
    original = (repo / "m.py").read_text()

    rc = engine_cli.main(["resume", thread, "--thread-store", str(store), "--checkpoint-id", "1f1e0166-6fc4-652f-8001-a08c10a1970c"])
    text = "".join(capsys.readouterr())
    assert rc != 0 and "mismatch" in text
    assert (repo / "m.py").read_text() == original
    assert not (store / thread / "verdict.json").exists()

    delta = store / thread / "stage_delta" / "files" / "m.py"
    delta.write_text(M_PY.replace("return x + 1", "return x + 9"))
    rc = engine_cli.main(["resume", thread, "--thread-store", str(store), "--checkpoint-id", interrupt])
    text = "".join(capsys.readouterr())
    assert rc != 0 and "tree digest" in text
    assert (repo / "m.py").read_text() == original
    assert not (store / thread / "verdict.json").exists()

    plan = launch.plan_agent_resume(repo, found[0], state=tmp_path / "ui")
    assert plan.checkpoint_id == interrupt
    assert "--checkpoint-id" in plan.argv and interrupt in plan.argv
    assert "--proposer-command" not in plan.argv


def test_pipeline_delta_approval_with_checkpoint_mismatch_refuses_exit4_before_gate(tmp_path, monkeypatch, capsys):
    """A resume approval is bound to this thread's recorded interrupt before any gate work."""
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    thread, _interrupt = _park(repo, store)
    original = (repo / "m.py").read_bytes()

    rc = engine_cli.main([
        "resume", thread, "--engine", "pipeline", "--thread-store", str(store),
        "--checkpoint-id", "1f1e0166-6fc4-652f-8001-a08c10a1970c",
        "--approve-deltas", "0" * 64,
    ])
    message = "".join(capsys.readouterr())
    assert rc == 4, message
    assert "checkpoint id mismatch" in message
    assert (repo / "m.py").read_bytes() == original
    assert not (store / thread / "verdict.json").exists()
    assert not list((tmp_path / "state").rglob("out.json"))


def test_pipeline_resume_hash_mismatch_is_unapproved_and_prints_canonical_digest(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    deltas = [{
        "id": "d1", "symbol": "m.add_one", "kind": "behavior", "claim": "returns x + 2",
        "input_domain": "x is an int", "pre": "x + 1", "post": "x + 2",
    }]
    thread, interrupt = _park(repo, store, deltas=deltas, replacement="return x + (1)")
    original = (repo / "m.py").read_bytes()
    from hlith.contract.effects import delta_set_sha256

    canonical = delta_set_sha256(deltas)

    rc = engine_cli.main([
        "resume", thread, "--engine", "pipeline", "--thread-store", str(store),
        "--checkpoint-id", interrupt, "--approve-deltas", "0" * 64,
    ])
    output = "".join(capsys.readouterr())
    assert rc == 12, output
    assert canonical in output
    assert (repo / "m.py").read_bytes() == original
    recorded = json.loads((store / thread / "verdict.json").read_text())
    assert recorded["decision"]["outcome"] == "refused"
    artifacts = list((tmp_path / "state").rglob("out.json"))
    assert len(artifacts) == 1
    artifact = json.loads(artifacts[0].read_text())
    assert artifact["effect"]["delta_set_sha256"] == canonical
    assert any(row["id"] == "deltas-confirmed" and row["verdict"] == "unverified" for row in artifact["obligations"])


def test_pipeline_resume_matching_hash_does_not_override_a_refuted_effect(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    deltas = [{
        "id": "d1", "symbol": "m.add_one", "kind": "behavior", "claim": "returns x + 2",
        "input_domain": "x is an int", "pre": "x + 1", "post": "x + 2",
    }]
    thread, interrupt = _park(repo, store, deltas=deltas)
    from hlith.contract.effects import delta_set_sha256

    rc = engine_cli.main([
        "resume", thread, "--engine", "pipeline", "--thread-store", str(store),
        "--checkpoint-id", interrupt, "--approve-deltas", delta_set_sha256(deltas),
    ])
    output = "".join(capsys.readouterr())
    assert rc == 10, output
    assert (repo / "m.py").read_text() == M_PY
    artifact = json.loads(next((tmp_path / "state").rglob("out.json")).read_text())
    assert not any(row["id"] == "deltas-confirmed" for row in artifact["obligations"])
    assert any(row["verdict"] == "refuted" for row in artifact["obligations"] if row["id"] != "deltas-confirmed")


def test_resume_rebuilds_the_captured_diff_and_does_not_touch_the_target(tmp_path, monkeypatch):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    thread, interrupt = _park(repo, store)
    original = (repo / "m.py").read_text()
    wr = resume_captured_worker(repo, thread, store, checkpoint_id=interrupt)
    try:
        assert "return x + 2" in wr.effect.unified_diff
        assert wr.effect.touched_files == ("m.py",) or "m.py" in wr.effect.touched_files
        assert wr.graph.interrupt_checkpoint_id == interrupt
        assert wr.graph.proposer is None  # patch-graph interrupt: no proposer is called on resume
        assert (repo / "m.py").read_text() == original
    finally:
        wr.graph.close()
    assert not (store / thread / "verdict.json").exists()


def test_captured_effect_refuses_a_copied_thread_store_before_gate(tmp_path, monkeypatch):
    """A copied checkpoint cannot be rebound to a different host-selected thread store."""
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    thread, interrupt = _park(repo, store)
    copied = tmp_path / "copied-store"
    copied.mkdir(mode=0o700)
    shutil.copytree(store / thread, copied / thread)
    original = (repo / "m.py").read_bytes()

    with pytest.raises(RuntimeBoundary, match="thread store does not match"):
        resume_captured_worker(repo, thread, copied, checkpoint_id=interrupt)

    assert (repo / "m.py").read_bytes() == original
    assert not (copied / thread / "verdict.json").exists()
    assert not list((tmp_path / "state").rglob("out.json"))


def test_checkpoint_resume_reaches_the_gate_and_does_not_record_an_interrupted_verdict(tmp_path, monkeypatch, capsys):
    """The default resume must hand the captured diff to the gate.

    Where Landlock exists, ``return x + 2`` has to be a semantic refutation (exit 10). Where
    ``landlock_create_ruleset`` is ENOSYS, the checkers cannot run: the gate must still refuse, as the
    typed host BOUNDARY (exit 4, ``host-confinement-unavailable``; abf19339 maps a launcher-authored
    confinement failure there, never to NOT-DERIVED 11), decide no obligation, and must not land or
    write an interrupted-before-gate verdict. That ENOSYS refusal is not evidence the regression
    itself was executed.
    """
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    thread, interrupt = _park(repo, store)
    original = (repo / "m.py").read_text()
    rc = engine_cli.main(["resume", thread, "--thread-store", str(store), "--checkpoint-id", interrupt])
    text = "".join(capsys.readouterr())
    assert "interrupted-before-gate" not in text
    assert "not mid-agent" not in text
    assert (repo / "m.py").read_text() == original
    verdict = json.loads((store / thread / "verdict.json").read_text())
    assert verdict["source"] == "gate"
    assert verdict["decision"]["outcome"] != "landed"
    assert verdict["decision"]["exit_status"] == rc
    assert rc != 0
    artifacts = list((tmp_path / "state").rglob("out.json"))
    assert artifacts, text
    art = json.loads(artifacts[-1].read_text())
    assert art["outcome"] == verdict["decision"]["outcome"]
    assert "return x + 2" in art["effect"]["unified_diff"]
    assert art.get("effect_account") is not None
    assert "interrupted-before-gate" not in art.get("blocking", [])
    prov = art.get("proposer_provenance") or {}
    assert prov.get("counts_as_e1") is False
    assert prov.get("resumed_from") == "effect-interrupt"
    if landlock_enosys():
        assert rc == 4, text
        assert art["outcome"] == "refused" and art["exit_status"] == 4, art
        assert verdict["decision"]["blocking"][0] == "host-confinement-unavailable", verdict
        assert "landlock-unavailable" in verdict["decision"]["blocking"][1], verdict
        assert "verification-failed" not in verdict["decision"]["blocking"]
        assert art["obligations"] == [], art
    else:
        assert rc == 10, text
        assert art.get("obligations"), art
        assert "verification-failed" not in verdict["decision"]["blocking"]
    sealed = (store / thread / "verdict.json").read_bytes()
    rc2 = engine_cli.main(["resume", thread, "--thread-store", str(store), "--checkpoint-id", interrupt])
    text2 = "".join(capsys.readouterr())
    assert "recorded verdict kept" in text2
    assert rc2 == rc
    assert (store / thread / "verdict.json").read_bytes() == sealed
    # A finished checkpoint must remain recognizable for authenticated, read-only replay,
    # but must not be offered again as an unfinished resumable action in Glass Box.
    desc_done = describe_thread(thread, store)
    assert desc_done["kind"] == "effect-interrupt" and desc_done["has_verdict"]
    assert captured_interrupts(_run_meta(repo, store)) == []
    wrong_after = engine_cli.main(["resume", thread, "--thread-store", str(store),
                                   "--checkpoint-id", "1f1e0166-6fc4-652f-8001-a08c10a1970c"])
    wrong_text = "".join(capsys.readouterr())
    assert wrong_after != rc and "mismatch" in wrong_text
    missing_after = engine_cli.main(["resume", thread, "--thread-store", str(store)])
    missing_text = "".join(capsys.readouterr())
    assert missing_after != rc and "--checkpoint-id" in missing_text
    assert (store / thread / "verdict.json").read_bytes() == sealed
    assert (repo / "m.py").read_text() == original
    assert os.environ["HLITH_STATE_DIR"]


def test_finished_effect_without_recorded_verdict_refuses_before_any_gate(tmp_path, monkeypatch, capsys):
    """Deleting a verdict from a finished checkpoint must not allow a new verdict."""
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    thread, interrupt = _park(repo, store)
    before = (repo / "m.py").read_bytes()
    meta_path = store / thread / "meta.json"
    meta = json.loads(meta_path.read_text())
    meta.update(finished=True, final_checkpoint_id="done-checkpoint")
    meta_path.write_text(json.dumps(meta))
    assert not (store / thread / "verdict.json").exists()
    desc = describe_thread(thread, store)
    assert desc["kind"] == "other" and desc["finished"] and not desc["has_verdict"]
    assert captured_interrupts(_run_meta(repo, store)) == []
    with pytest.raises(RuntimeBoundary, match="finished effect interrupt cannot re-enter"):
        resume_captured_worker(repo, thread, store, checkpoint_id=interrupt)
    # The public default CLI refuses instead of raising an argparse SystemExit.
    rc = engine_cli.main(["resume", thread, "--thread-store", str(store),
                          "--checkpoint-id", interrupt])
    text = "".join(capsys.readouterr())
    assert rc != 0 and "recorded verdict" in text
    assert (repo / "m.py").read_bytes() == before
    assert not (store / thread / "verdict.json").exists()


def test_describe_thread_uses_injected_host_state_for_verdict_authentication(tmp_path, monkeypatch):
    """A caller's host key must authenticate the recorded verdict it is describing."""
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "default-state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    (repo / "m.py").write_text(M_PY.replace("return x + 1", "return x + 2"))
    patch = subprocess.run(["git", "-C", str(repo), "diff"], check=True, capture_output=True).stdout
    _git(repo, "checkout", "-q", ".")
    run = park_layer1_patch(
        repo, store, patch,
        manifest_bytes=json.dumps({"paths": {"m.py": ["modify"]}}).encode(),
    )

    class InjectedHostState:
        def key(self, _purpose):
            return b"injected-checkpoint-key-32-bytes!"

    host_state = InjectedHostState()
    decision = {"outcome": "refused", "exit_status": 10}
    try:
        from hlith.agent.checkpoint import record_verdict

        record_verdict(run.graph, decision, host_state=host_state)
        assert run.graph.resume_error is None
        described = describe_thread(run.graph.thread_id, store, host_state=host_state)
        assert described["has_verdict"] is True
        assert described["verdict"] == decision
    finally:
        run.graph.close()


@pytest.mark.parametrize("case", ["meta", "verdict", "decision", "checkpoint_id"])
def test_deep_checkpoint_json_is_a_boundary_not_a_traceback(tmp_path, monkeypatch, capsys, case):
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    thread, interrupt = _park(repo, store)
    if case == "checkpoint_id":
        # 50k-deep nested list as raw JSON text: json.dumps of such an object raises RecursionError on CPython 3.13 inside the
        # fixture itself (before the engine is reached), so the hostile value is spliced into the serialized meta instead.
        meta_path = store / thread / "meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["interrupt_checkpoint_id"] = "__NESTED__"
        nested_json = "[" * 50_000 + "0" + "]" * 50_000
        meta_path.write_text(json.dumps(meta).replace('"__NESTED__"', nested_json), encoding="utf-8")
    elif case == "decision":
        nested_value = b'{"a":' * 50_000 + b"0" + b"}" * 50_000
        payload = b'{"decision":' + nested_value + b',"decision_sha256":"","source":"gate","mac":"forged"}'
        json_name = "verdict.json"
    else:
        payload = b"[" * 200_000 + b"0" + b"]" * 200_000
        json_name = f"{case}.json"
    if case != "checkpoint_id":
        (store / thread / json_name).write_bytes(payload)

    rc = engine_cli.main([
        "resume", thread, "--engine", "pipeline", "--thread-store", str(store),
        "--checkpoint-id", interrupt,
    ])
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert rc == 4
    assert "Traceback" not in output
    assert "boundary" in output
    if case == "checkpoint_id":
        assert len(output) < 1000, f"malformed checkpoint metadata diagnostic is {len(output)} chars: {output[:200]!r}"


def test_pipeline_cli_replays_verdict_with_operator_host_state(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("HLITH_STATE_DIR", raising=False)
    ui_state = tmp_path / "ui-state"
    monkeypatch.setenv("HLITH_UI_STATE", str(ui_state))
    repo = _repo(tmp_path)
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    (repo / "m.py").write_text(M_PY.replace("return x + 1", "return x + 2"))
    patch = subprocess.run(["git", "-C", str(repo), "diff"], check=True, capture_output=True).stdout
    _git(repo, "checkout", "-q", ".")
    run = park_layer1_patch(
        repo, store, patch,
        manifest_bytes=json.dumps({"paths": {"m.py": ["modify"]}}).encode(),
    )
    thread, interrupt = run.graph.thread_id, run.graph.interrupt_checkpoint_id
    try:
        from hlith.agent.checkpoint import record_verdict
        from hlith.hostio import LocalHostState

        decision = {"outcome": "refused", "exit_status": 10}
        record_verdict(run.graph, decision, host_state=LocalHostState(ui_state / "host"))
        assert run.graph.resume_error is None
        rc = engine_cli.main([
            "resume", thread, "--engine", "pipeline", "--thread-store", str(store),
            "--checkpoint-id", interrupt,
        ])
        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert rc == 10
        assert "recorded verdict kept" in output
    finally:
        run.graph.close()
