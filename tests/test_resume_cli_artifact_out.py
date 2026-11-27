from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import sys

import pytest

from hlith.operator import capabilities, engine_cli
from hlith.operator.api import OperatorApi
import hlith.agent as agent
from hlith.contract.errors import EXIT_ARTIFACT_COPY, EXIT_BOUNDARY
from hlith.runtime import RuntimeBoundary


def _mock_pipeline_resume_checkpoint(monkeypatch):
    from hlith.agent import checkpoint

    monkeypatch.setattr(checkpoint, "describe_thread", lambda *_a, **_kw: {
        "has_verdict": False, "finished": False, "interrupt_checkpoint_id": None,
        "kind": "agent", "captured_mac": False,
    })


def test_resume_cli_preflights_artifact_destination_before_continuing_thread(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    source = tmp_path / "run-artifact.json"
    source.write_text('{"outcome":"landed"}\n')
    calls: list[str] = []
    out = SimpleNamespace(
        problems=(), run_dir=tmp_path / "run", exit_status=0,
        receipt=SimpleNamespace(run_id="run-1"), gate=SimpleNamespace(blocking=()),
        artifact_path=source,
    )
    monkeypatch.setattr(agent, "thread_target", lambda *_: target)
    _mock_pipeline_resume_checkpoint(monkeypatch)
    monkeypatch.setattr(engine_cli, "dirty_repo_reason", lambda *_: None)
    monkeypatch.setattr(capabilities, "default_capabilities", lambda **_: object())
    monkeypatch.setattr(OperatorApi, "run_inline", lambda *_a, **_kw: (calls.append("run"), out)[1])
    monkeypatch.setattr(OperatorApi, "inspect", lambda *_: SimpleNamespace(label="resume thread-0123456789ab", notes=()))

    def args_for(destination: Path):
        return SimpleNamespace(
            allow_unconfined_proposer=False, proposer_command=None, hosted_agent_config=None, redo_inflight=False,
            checkpoint_id=None, approve_deltas=None, invocation_id=None,
            thread_store=tmp_path / "store", thread_id="thread-0123456789ab", source_repo=None,
            surface_mode="standalone", label=None, worker_ro=[], extra_sys_path=[],
            timeout=3, target_python=sys.executable, run_link=None, artifact_out=destination,
        )

    # Negative control: a usable operator path receives the artifact after a successful resume.
    valid = tmp_path / "valid" / "result.json"
    valid.parent.mkdir()
    assert engine_cli._resume_via_pipeline(args_for(valid), None) == 0
    assert valid.read_bytes() == source.read_bytes()

    # Falsifier: an unusable destination must be rejected before the resume operation starts.
    calls.clear()
    invalid = tmp_path / "missing-parent" / "result.json"
    from io import StringIO
    import contextlib
    stderr = StringIO()
    with contextlib.redirect_stderr(stderr):
        rc = engine_cli._resume_via_pipeline(args_for(invalid), None)
    assert rc == EXIT_BOUNDARY
    assert calls == [], "resume ran before validating --artifact-out; CLI then failed copying the receipt"
    assert "--artifact-out parent must already exist" in stderr.getvalue()
    assert not any(p.name.startswith(".hlith-preflight-") for p in tmp_path.iterdir())


def test_resume_cli_returns_distinct_successful_operation_artifact_copy_failure(tmp_path, monkeypatch, capsys):
    target = tmp_path / "target"
    target.mkdir()
    source = tmp_path / "original-artifact.json"
    source.write_text('{"outcome":"landed"}\n')
    args = SimpleNamespace(
        allow_unconfined_proposer=False, proposer_command=None, hosted_agent_config=None, redo_inflight=False,
        checkpoint_id=None, approve_deltas=None, invocation_id=None,
        thread_store=tmp_path / "store", thread_id="thread-0123456789ab", source_repo=None,
        surface_mode="standalone", label=None, worker_ro=[], extra_sys_path=[],
        timeout=3, target_python=sys.executable, run_link=None,
        artifact_out=tmp_path / "result.json",
    )
    out = SimpleNamespace(problems=(), run_dir=tmp_path / "run", exit_status=0,
        receipt=SimpleNamespace(run_id="run-1"), gate=SimpleNamespace(blocking=()), artifact_path=source)
    calls: list[str] = []
    monkeypatch.setattr(agent, "thread_target", lambda *_: target)
    _mock_pipeline_resume_checkpoint(monkeypatch)
    monkeypatch.setattr(engine_cli, "dirty_repo_reason", lambda *_: None)
    monkeypatch.setattr(capabilities, "default_capabilities", lambda **_: object())
    monkeypatch.setattr(OperatorApi, "run_inline", lambda *_a, **_kw: (calls.append("run"), out)[1])
    monkeypatch.setattr(OperatorApi, "inspect", lambda *_: SimpleNamespace(label="resume thread-0123456789ab", notes=()))
    monkeypatch.setattr(engine_cli, "_atomic_write_file", lambda *_a, **_kw: (_ for _ in ()).throw(OSError(28, "No space left")))

    assert engine_cli._resume_via_pipeline(args, None) == EXIT_ARTIFACT_COPY
    captured = capsys.readouterr()
    assert calls == ["run"]
    assert "operation SUCCEEDED, artifact copy FAILED" in captured.err
    assert str(source) in captured.err
    assert "Traceback" not in captured.err


def test_run_pipeline_preflights_outputs_before_operator_api(tmp_path, monkeypatch, capsys):
    target = tmp_path / "repo"
    target.mkdir()
    calls: list[str] = []
    monkeypatch.setattr(OperatorApi, "run_inline", lambda *_a, **_kw: calls.append("run"))

    rc = engine_cli.main([
        "run", "--engine", "pipeline", "--repo", str(target), "--worker-cmd", "true",
        "--artifact-out", str(target / "artifact.json"),
    ])

    assert rc == EXIT_BOUNDARY
    assert calls == []
    assert not (target / "artifact.json").exists()
    assert "--artifact-out must be outside protected tree" in capsys.readouterr().err


def test_legacy_run_preflights_outputs_before_engine_work(tmp_path, monkeypatch, capsys):
    target = tmp_path / "repo"
    target.mkdir()
    calls: list[str] = []
    monkeypatch.setattr(engine_cli, "run_pipeline", lambda *_a, **_kw: calls.append("run"))

    rc = engine_cli.main([
        "run", "--engine", "legacy", "--repo", str(target), "--worker-cmd", "true",
        "--artifact-out", str(target / "artifact.json"),
    ])

    assert rc == EXIT_BOUNDARY
    assert calls == []
    assert not (target / "artifact.json").exists()
    assert "--artifact-out must be outside protected tree" in capsys.readouterr().err


def test_legacy_run_preflights_possible_account_sidecar(tmp_path, monkeypatch, capsys):
    target = tmp_path / "repo"
    target.mkdir()
    destination = tmp_path / "artifact.json"
    sidecar = destination.with_name(destination.name + ".account.json")
    sidecar.symlink_to(target / "mod.py")
    calls: list[str] = []
    monkeypatch.setattr(engine_cli, "run_pipeline", lambda *_a, **_kw: calls.append("run"))

    rc = engine_cli.main([
        "run", "--engine", "legacy", "--repo", str(target), "--worker-cmd", "true",
        "--artifact-out", str(destination),
    ])

    assert rc == EXIT_BOUNDARY
    assert calls == []
    assert not destination.exists()
    assert "account sidecar path traverses symlink" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--run-link", "--events-out"])
def test_run_pipeline_preflights_event_and_run_link_files_before_operator_api(tmp_path, monkeypatch, capsys, flag):
    target = tmp_path / "repo"
    target.mkdir()
    calls: list[str] = []
    monkeypatch.setattr(OperatorApi, "run_inline", lambda *_a, **_kw: calls.append("run"))
    extra = target / ("events.jsonl" if flag == "--events-out" else "run-link.json")

    artifact = tmp_path / "artifact.json"
    rc = engine_cli.main([
        "run", "--engine", "pipeline", "--repo", str(target), "--worker-cmd", "true",
        "--artifact-out", str(artifact), flag, str(extra),
    ])

    assert rc == EXIT_BOUNDARY
    assert calls == []
    assert not extra.exists()
    assert not artifact.exists()
    err = capsys.readouterr().err
    if flag == "--events-out":
        assert err == "hlith: boundary: --events-out is not supported by --engine pipeline; use --engine legacy\n"
    else:
        assert "must be outside protected tree" in err or "worker can access" in err


def test_run_pipeline_refuses_existing_run_link_before_operator_api(tmp_path, monkeypatch, capsys):
    target = tmp_path / "repo"
    target.mkdir()
    artifact = tmp_path / "artifact.json"
    link = tmp_path / "run-link.json"
    link.write_text("prior run")
    before = link.read_bytes()
    calls: list[str] = []
    monkeypatch.setattr(OperatorApi, "run_inline", lambda *_a, **_kw: calls.append("run"))

    rc = engine_cli.main([
        "run", "--engine", "pipeline", "--repo", str(target), "--worker-cmd", "true",
        "--artifact-out", str(artifact), "--run-link", str(link),
    ])

    assert rc == EXIT_BOUNDARY
    assert calls == []
    assert link.read_bytes() == before
    assert not artifact.exists()
    assert "--run-link already exists" in capsys.readouterr().err


def test_run_pipeline_refuses_symlinked_thread_store_before_operator_api(tmp_path, monkeypatch, capsys):
    target = tmp_path / "repo"
    target.mkdir()
    outside = tmp_path / "outside-store"
    outside.mkdir()
    store_link = tmp_path / "store-link"
    store_link.symlink_to(outside, target_is_directory=True)
    calls: list[str] = []
    monkeypatch.setattr(OperatorApi, "run_inline", lambda *_a, **_kw: calls.append("run"))

    rc = engine_cli.main([
        "run", "--engine", "pipeline", "--repo", str(target), "--worker-cmd", "true",
        "--artifact-out", str(tmp_path / "artifact.json"), "--thread-store", str(store_link),
    ])

    assert rc == EXIT_BOUNDARY
    assert calls == []
    assert "--thread-store path traverses symlink" in capsys.readouterr().err


def test_legacy_resume_preflights_artifact_before_agent_continuation(tmp_path, monkeypatch, capsys):
    from hlith import layer1

    target = tmp_path / "target"
    target.mkdir()
    store = tmp_path / "store"
    store.mkdir()
    monkeypatch.setattr(layer1, "thread_target", lambda *_: target)

    rc = engine_cli.main([
        "resume", "thread-0123456789ab", "--engine", "legacy", "--thread-store", str(store),
        "--proposer-command", f"{sys.executable} -c pass", "--artifact-out",
        str(tmp_path / "missing-parent" / "artifact.json"),
    ])

    assert rc == EXIT_BOUNDARY
    assert not (store / "thread-0123456789ab").exists()
    assert "--artifact-out parent must already exist" in capsys.readouterr().err


def test_preflight_rejects_symlink_destination_parent_and_thread_store(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked-outside"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(RuntimeBoundary, match="path traverses symlink"):
        engine_cli._preflight_destination(link / "artifact.json", "--artifact-out", protected=(target,), kind="file")
    with pytest.raises(RuntimeBoundary, match="path traverses symlink"):
        engine_cli._preflight_destination(link, "--thread-store", protected=(target,), kind="directory")


def test_atomic_artifact_write_cannot_follow_parent_replaced_after_preflight(tmp_path):
    protected = tmp_path / "repo"
    protected.mkdir()
    sentinel = protected / "artifact.json"
    sentinel.write_bytes(b"protected-before")
    output_parent = tmp_path / "out"
    output_parent.mkdir()
    destination = output_parent / "artifact.json"

    _, _, parent_directory = engine_cli._preflight_destination(
        destination, "--artifact-out", protected=(protected,), kind="file")
    output_parent.rename(tmp_path / "out-held")
    output_parent.symlink_to(protected, target_is_directory=True)

    with pytest.raises(OSError, match="changed after preflight"):
        engine_cli._atomic_write_file(destination, b"redirected", parent_directory=parent_directory)

    assert sentinel.read_bytes() == b"protected-before"
    assert (tmp_path / "out-held" / "artifact.json").read_bytes() == b"redirected"


def test_pipeline_resume_copy_cannot_be_redirected_into_protected_tree(tmp_path, monkeypatch, capsys):
    target = tmp_path / "target"
    target.mkdir()
    protected_artifact = target / "result.json"
    protected_artifact.write_bytes(b"protected-before")
    output_parent = tmp_path / "out"
    output_parent.mkdir()
    destination = output_parent / "result.json"
    source = tmp_path / "original-artifact.json"
    source.write_text('{"outcome":"landed"}\n')
    args = SimpleNamespace(
        allow_unconfined_proposer=False, proposer_command=None, hosted_agent_config=None, redo_inflight=False,
        checkpoint_id=None, approve_deltas=None, invocation_id=None,
        thread_store=tmp_path / "store", thread_id="thread-0123456789ab", source_repo=None,
        surface_mode="standalone", label=None, worker_ro=[], extra_sys_path=[],
        timeout=3, target_python=sys.executable, run_link=None, artifact_out=destination,
    )
    out = SimpleNamespace(problems=(), run_dir=tmp_path / "run", exit_status=0,
        receipt=SimpleNamespace(run_id="run-1"), gate=SimpleNamespace(blocking=()), artifact_path=source)

    def replace_output_parent(*_args, **_kwargs):
        output_parent.rename(tmp_path / "out-held")
        output_parent.symlink_to(target, target_is_directory=True)
        return out

    monkeypatch.setattr(agent, "thread_target", lambda *_: target)
    _mock_pipeline_resume_checkpoint(monkeypatch)
    monkeypatch.setattr(engine_cli, "dirty_repo_reason", lambda *_: None)
    monkeypatch.setattr(capabilities, "default_capabilities", lambda **_: object())
    monkeypatch.setattr(OperatorApi, "run_inline", replace_output_parent)
    monkeypatch.setattr(OperatorApi, "inspect", lambda *_: SimpleNamespace(label="resume thread-0123456789ab", notes=()))

    assert engine_cli._resume_via_pipeline(args, None) == EXIT_ARTIFACT_COPY
    assert protected_artifact.read_bytes() == b"protected-before"
    assert (tmp_path / "out-held" / "result.json").read_bytes() == source.read_bytes()
    captured = capsys.readouterr()
    assert "operation SUCCEEDED, artifact copy FAILED" in captured.err
    assert str(source) in captured.err
