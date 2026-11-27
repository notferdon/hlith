from __future__ import annotations

import subprocess

import pytest

from hlith.operator import engine_cli
from hlith.operator.api import OperatorApi
from hlith.operator.coordinator import RequestError


def test_run_help_explains_pipeline_default_and_explicit_legacy(capsys):
    with pytest.raises(SystemExit) as exc:
        engine_cli.main(["run", "--help"])

    assert exc.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "pipeline (default): runs through OperatorApi's trusted coordinator" in help_text
    assert "legacy: preserves the pre-pipeline direct `hlith run` path" in help_text
    assert "Pipeline resume binds --approve-deltas to the captured thread deltas" in help_text
    assert "a mismatch returns exit 12 with the canonical digest" in help_text
    assert "thread/checkpoint binding mismatch returns exit 4" in help_text
    assert "--events-out" in help_text and "use --engine legacy" in help_text
    assert "--run-id" in help_text and "use --run-link to learn it" in help_text
    assert "pipeline validates --patch as an external effect" in help_text
    assert "legacy checkpointed graph: use --engine legacy --layer1 langgraph" in help_text
    assert "--proposer-command is the pipeline LangGraph proposer" in help_text
    assert "--layer1 is legacy-only; pipeline mode refuses it" in help_text
    assert "durable LangGraph thread store for legacy --layer1 or pipeline proposer runs" in help_text


def test_unqualified_run_dispatches_to_pipeline_and_legacy_is_explicit(monkeypatch, tmp_path, capsys):
    engines: list[str] = []

    def stop_before_engine(_args, *, engine, **_kwargs):
        engines.append(engine)
        raise engine_cli.RuntimeBoundary("test stopped before engine execution")

    monkeypatch.setattr(engine_cli, "_preflight_cli_outputs", stop_before_engine)
    args = [
        "run", "--repo", str(tmp_path), "--worker-cmd", "python -c pass",
        "--artifact-out", str(tmp_path.parent / "out.json"),
    ]

    monkeypatch.setattr(engine_cli, "_run_via_pipeline", lambda _args: 73)
    assert engine_cli.main(args) == 73
    assert engines == []

    assert engine_cli.main([*args[:1], "--engine", "legacy", *args[1:]]) == 4
    assert engines == ["legacy"]
    assert "test stopped before engine execution" in capsys.readouterr().err


def test_pipeline_run_id_refuses_with_boundary_exit(monkeypatch, tmp_path, capsys):
    rc = engine_cli.main([
        "run", "--repo", str(tmp_path), "--worker-cmd", "python -c pass",
        "--artifact-out", str(tmp_path.parent / "run-id-artifact.json"), "--run-id", "run-123456789abc",
    ])

    assert rc == 4
    err = capsys.readouterr().err
    assert "--run-id cannot be selected with --engine pipeline" in err
    assert "use --run-link to learn it" in err and "--engine legacy to supply one" in err
    assert not (tmp_path.parent / "run-id-artifact.json").exists()


def test_pipeline_events_out_refuses_before_creating_output(monkeypatch, tmp_path, capsys):
    events = tmp_path / "events.jsonl"
    rc = engine_cli.main([
        "run", "--repo", str(tmp_path), "--worker-cmd", "python -c pass",
        "--artifact-out", str(tmp_path.parent / "events-artifact.json"), "--events-out", str(events),
    ])

    assert rc == 4
    assert "--events-out is not supported by --engine pipeline" in capsys.readouterr().err
    assert not events.exists()
    assert not (tmp_path.parent / "events-artifact.json").exists()


def test_pipeline_layer1_refuses_instead_of_silently_ignoring_it(tmp_path, monkeypatch, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
    (repo / "module.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "module.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "base"], check=True)
    calls = []

    def stop_before_run(*_args, **_kwargs):
        calls.append("run_inline")
        raise RequestError("test stub: engine not run")

    monkeypatch.setattr(OperatorApi, "run_inline", stop_before_run)
    artifact = tmp_path / "layer1-artifact.json"
    rc = engine_cli.main([
        "run", "--repo", str(repo), "--worker-cmd", "python -c pass",
        "--artifact-out", str(artifact), "--layer1", "langgraph",
    ])

    assert not calls, "pipeline ignored --layer1 and reached OperatorApi"
    assert rc == 4
    assert "--layer1 is not supported by --engine pipeline" in capsys.readouterr().err
    assert not artifact.exists()


@pytest.mark.parametrize("engine", [None, "legacy"])
def test_missing_patch_file_is_a_usage_error_not_an_execution_boundary(tmp_path, capsys, engine):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
    (repo / "module.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "module.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "base"], check=True)
    artifact = tmp_path / "missing-patch-artifact.json"

    argv = ["run"]
    if engine is not None:
        argv.extend(("--engine", engine))
    argv.extend(("--repo", str(repo), "--patch", str(tmp_path / "missing.patch"), "--artifact-out", str(artifact)))
    rc = engine_cli.main(argv)

    assert rc == 2
    assert "operator input does not exist" in capsys.readouterr().err
    assert not artifact.exists()


def test_nonexistent_repo_path_is_a_usage_error_not_an_execution_boundary(tmp_path, capsys):
    artifact = tmp_path / "missing-repo-artifact.json"

    rc = engine_cli.main([
        "run", "--repo", str(tmp_path / "missing-repo"), "--worker-cmd", "true",
        "--artifact-out", str(artifact),
    ])

    assert rc == 2
    assert "repository path does not exist" in capsys.readouterr().err
    assert not artifact.exists()


def test_legacy_invalid_run_id_is_usage_error_without_traceback(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init", "-q", "-b", "main"], check=True)
    (repo / "module.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(repo), "add", "module.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "base"], check=True)
    with pytest.raises(SystemExit) as exc:
        engine_cli.main([
            "run", "--engine", "legacy", "--repo", str(repo),
            "--worker-cmd", "true", "--artifact-out", str(tmp_path / "artifact.json"), "--run-id", "fp-r1",
        ])

    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "not a run id: 'fp-r1'" in err
    assert "Traceback" not in err
    assert not (tmp_path / "artifact.json").exists()


def test_pipeline_resume_unknown_thread_refuses_before_gate_or_outputs(tmp_path, capsys):
    thread_store = tmp_path / "threads"
    artifact_out = tmp_path / "artifact.json"
    run_link = tmp_path / "run-link.json"
    rc = engine_cli.main([
        "resume", "hlith-0123456789abcdef0123", "--engine", "pipeline",
        "--thread-store", str(thread_store), "--artifact-out", str(artifact_out),
        "--run-link", str(run_link), "--approve-deltas", "a" * 64,
    ])

    assert rc == 4
    message = capsys.readouterr().err
    assert "thread hlith-0123456789abcdef0123 not found" in message
    assert not thread_store.exists()
    assert not artifact_out.exists()
    assert not run_link.exists()


def test_pipeline_resume_malformed_delta_hash_is_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        engine_cli.main([
            "resume", "hlith-0123456789abcdef0123", "--engine", "pipeline",
            "--thread-store", str(tmp_path / "threads"), "--approve-deltas", "not-a-sha256",
        ])

    assert exc.value.code == 2
    message = capsys.readouterr().err
    assert "--approve-deltas must be a 64-hex sha256" in message
    assert not (tmp_path / "threads").exists()
