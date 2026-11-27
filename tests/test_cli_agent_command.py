from __future__ import annotations

import json
import shlex
import subprocess
import tempfile
import sys
from pathlib import Path

import pytest

from hlith import cli, differential
from hlith.proposer import CommandProposer
from hlith.runtime import RuntimeBoundary
from hlith.summary import report
from hlith.types import Verdict


def _engine_main(argv, capsys):
    """The engine module's own dispatcher (not the public `hlith` CLI): returns (rc, stderr)."""
    from hlith.operator import engine_cli

    rc = engine_cli.main(argv)
    return rc, capsys.readouterr().err


def _assert_run_not_offered(argv, capsys):
    """Review-only: the public `hlith` CLI has no such subcommand (argparse exit 2, `invalid choice`)."""
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    assert e.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def _marker_proposer(tmp_path, name="proposer-ran"):
    """A proposer command that leaves a marker if it is ever executed."""
    marker = tmp_path / name
    script = tmp_path / f"{name}.py"
    script.write_text(f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\nprint('{{}}')\n")
    return shlex.join([sys.executable, str(script)]), marker


def test_proposer_command_is_exclusive_and_requires_langgraph(tmp_path, capsys):
    """Retargeted (review-only). Was: `hlith run` rejected --proposer-command with --worker-cmd (exit 2) and --engine legacy without
    --layer1 langgraph (exit 2). Now: the public CLI has no `run`; the engine parser still rejects the exclusive pair (exit 2), and the
    legacy combination is refused as a review-only boundary (exit 4) before anything is written."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _assert_run_not_offered(["run", "--repo", str(repo), "--worker-cmd", "true", "--proposer-command", "true",
                             "--artifact-out", str(tmp_path / "artifact.json")], capsys)
    with pytest.raises(SystemExit) as e:
        _engine_main(["run", "--repo", str(repo), "--worker-cmd", "true", "--proposer-command", "true",
                      "--artifact-out", str(tmp_path / "artifact.json")], capsys)
    assert e.value.code == 2
    assert "not allowed with argument --worker-cmd" in capsys.readouterr().err
    rc, err = _engine_main(["run", "--engine", "legacy", "--repo", str(repo), "--proposer-command", "true",
                            "--artifact-out", str(tmp_path / "artifact.json")], capsys)
    assert rc == 4 and "Hlith Review is read-only" in err
    assert not (tmp_path / "artifact.json").exists()


def test_proposer_command_hash_is_canonical_argv_only():
    a = CommandProposer([sys.executable, "-c", "pass"])
    b = CommandProposer([sys.executable, "-c", "pass"])
    c = CommandProposer([sys.executable, "-c", "print(1)"])
    assert a.argv_sha256 == b.argv_sha256
    assert a.argv_sha256 != c.argv_sha256
    assert len(a.argv_sha256) == 64


def test_derive_proposer_paths_include_command_code_data_and_script_directory_but_not_python_runtime(tmp_path):
    script = tmp_path / "agent.py"
    data = tmp_path / "agent-data.json"
    script.write_text("pass\n")
    data.write_text("{}\n")
    proposer = CommandProposer([sys.executable, str(script), str(data)])
    paths = cli._derive_proposer_paths([], (), None, None, proposer)
    assert str(script.resolve()) in paths
    assert str(data.resolve()) in paths
    assert str(script.parent.resolve()) in paths
    assert str(Path(sys.executable).resolve()) not in paths


def _differential_roots(tmp_path):
    base, post = tmp_path / "base", tmp_path / "post"
    base.mkdir()
    post.mkdir()
    (base / "m.py").write_text("def f(x: int) -> int:\n    return x + 1\n")
    (post / "m.py").write_text("def f(x: int) -> int:\n    y = x + 1\n    return y\n")
    return base, post


def test_differential_without_any_proposer_path_fails_closed(tmp_path):
    base, post = _differential_roots(tmp_path)
    result = differential.run_differential(
        base_root=str(base), post_root=str(post), module="m", function="f",
        proposer_paths=[], scratch=str(tmp_path / "scratch"), max_examples=2,
    )
    assert result.verdict is Verdict.UNVERIFIED
    assert "proposer paths absent on host" in result.stop_reason


def test_differential_refuses_when_a_proposer_path_is_readable_in_the_confined_profile(tmp_path):
    base, post = _differential_roots(tmp_path)
    script = base / "m.py"  # base is explicitly granted read-only to the confined differential checker
    result = differential.run_differential(
        base_root=str(base), post_root=str(post), module="m", function="f",
        proposer_paths=[str(script)],
        scratch=str(tmp_path / "scratch"), max_examples=2, require_impacted_slice=False,
    )
    assert result.verdict is Verdict.UNVERIFIED
    assert "proposer paths readable inside profile" in result.stop_reason
    assert result.provenance.proposer_paths_readable is True


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _tiny_repo(repo: Path) -> None:
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "e1cli-test")
    _git(repo, "config", "user.email", "e1cli-test@invalid.local")
    (repo / "mod.py").write_text("def f(x: int) -> int:\n    return x + 1\n")
    (repo / "test_mod.py").write_text("from mod import f\n\ndef test_f():\n    assert f(1) == 2\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")


def test_local_proposer_and_human_patch_use_the_same_derive_gate_verdict(tmp_path, capsys):
    """Retargeted (review-only). Was: a local proposer's patch and the same human patch reached the same derive/gate verdict through
    `hlith run`. Now neither route exists: both are refused identically (exit 4, read-only boundary) before the proposer executes, and
    neither writes an artifact or thread store. The supplied-patch review path is `hlith check` (tested elsewhere)."""
    patch_source = tmp_path / "patch-source"
    _tiny_repo(patch_source)
    (patch_source / "mod.py").write_text("def f(x: int) -> int:\n    value = x + 1\n    return value\n")
    patch = tmp_path / "change.patch"
    manifest = tmp_path / "change.manifest.json"
    patch.write_text(_git(patch_source, "diff") + "\n")
    manifest.write_text(json.dumps({"paths": {"mod.py": ["modify"]}}))
    agent_command, marker = _marker_proposer(tmp_path)
    agent_repo, human_repo = tmp_path / "agent-repo", tmp_path / "human-repo"
    _tiny_repo(agent_repo)
    _tiny_repo(human_repo)
    agent_artifact, human_artifact = tmp_path / "agent-artifact.json", tmp_path / "human-artifact.json"
    agent_argv = ["run", "--repo", str(agent_repo), "--proposer-command", agent_command, "--artifact-out", str(agent_artifact),
                  "--thread-store", str(tmp_path / "agent-store"), "--target-python", sys.executable]
    human_argv = ["run", "--repo", str(human_repo), "--patch", str(patch), "--manifest", str(manifest), "--artifact-out", str(human_artifact),
                  "--thread-store", str(tmp_path / "human-store"), "--target-python", sys.executable]
    for argv in (agent_argv, human_argv):
        _assert_run_not_offered(argv, capsys)
    (agent_rc, agent_err), (human_rc, human_err) = _engine_main(agent_argv, capsys), _engine_main(human_argv, capsys)
    assert agent_rc == human_rc == 4 and agent_err == human_err and "Hlith Review is read-only" in agent_err
    assert not marker.exists(), "the proposer ran although the route is not offered"
    for path in (agent_artifact, human_artifact, tmp_path / "agent-store", tmp_path / "human-store"):
        assert not path.exists(), path
    assert _git(agent_repo, "status", "--porcelain") == "" and _git(human_repo, "status", "--porcelain") == ""


def test_proposer_command_cannot_be_loaded_from_repo_or_worker_grant(tmp_path):
    repo = tmp_path / "repo"
    grant = tmp_path / "grant"
    repo.mkdir()
    grant.mkdir()
    script = repo / "agent.py"
    script.write_text("pass\n")
    granted_script = grant / "agent.py"
    granted_script.write_text("pass\n")
    guard = cli._guard_proposer_argv
    system_python = str(Path(sys.base_prefix) / "bin" / "python3")
    with pytest.raises(RuntimeBoundary, match="inside the target repository"):
        guard([system_python, str(script)], repo, ())
    with pytest.raises(RuntimeBoundary, match="worker-readable grant"):
        guard([system_python, str(granted_script)], repo, (grant,))


def test_proposer_command_cannot_be_loaded_from_saved_stage(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    stage = tmp_path / "thread" / "stage"
    stage.mkdir(parents=True)
    script = stage / "agent.py"
    script.write_text("pass\n")
    system_python = str(Path(sys.base_prefix) / "bin" / "python3")
    with pytest.raises(RuntimeBoundary, match="inside a worker-readable path"):
        cli._guard_proposer_argv([system_python, str(script)], repo, (), forbidden=(stage,))


def test_agent_report_names_thread_argv_hash_turns_files_retry_and_refusal(tmp_path):
    art = {
        "outcome": "refused", "exit_status": 12, "landed_commit": None,
        "blocking": ["unverified:effect"],
        "obligations": [{"id": "unverified:effect", "verdict": "unverified", "witness": None,
                         "stop_reason": "no independent check", "claim": "independent check runs", "evidence": None}],
        "effect": {"patch_sha256": "a" * 64, "touched_files": ["pkg/a.py"]},
        "graph": {"thread_id": "hlith-test", "proposer": {"command_argv_sha256": "b" * 64, "turns": 3,
                    "redo_inflight": True, "redone_turn": 1, "allow_unconfined": True}},
    }
    out = report(art, 12, tmp_path / "artifact.json")
    assert "thread=hlith-test" in out and f"argv_sha256={'b' * 64}" in out and "turns=3" in out
    assert "agent files: pkg/a.py" in out and "agent refusal reasons: unverified:effect" in out
    assert "--redo-inflight repeated turn 1" in out
    assert "agent warning: operator allowed an interpreter form; it runs code outside confinement" in out


@pytest.mark.parametrize("form", ["python-c", "python-s", "python-C", "env-s", "shell-c", "env-chdir", "python-module"])
def test_interpreter_indirection_into_repo_requires_explicit_unconfined_opt_in(tmp_path, form):
    import shutil

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "evil.py").write_text("from pathlib import Path\nPath('canary').write_text('ran')\n")
    outside = tmp_path / "external.py"
    outside.write_text("pass\n")
    python = sys.executable
    env = shutil.which("env") or "/usr/bin/env"
    shell = shutil.which("sh") or "/bin/sh"
    commands = {
        "python-c": [python, "-c", f"exec(open({str(repo / 'evil.py')!r}).read())"],
        "python-s": [python, "-S", str(outside)],
        "python-C": [python, "-C", tempfile.gettempdir()],
        "env-s": [env, "-S", f"{python} {repo / 'evil.py'}"],
        "shell-c": [shell, "-c", f"{python} {repo / 'evil.py'}"],
        "env-chdir": [env, f"--chdir={repo}", python, "evil.py"],
        "python-module": [python, "-m", "evil"],
    }

    with pytest.raises(RuntimeBoundary, match="runs code outside confinement"):
        cli._guard_proposer_argv(commands[form], repo, ())
    assert not (repo / "canary").exists()


def test_unconfined_interpreter_opt_in_is_explicit_and_cli_documented(tmp_path, capsys):
    """Retargeted (review-only). The guard's explicit opt-in is unchanged. Was: `hlith run/resume --help` documented
    --allow-unconfined-proposer and a misuse exited 2. Now the public CLI offers no run/resume at all, and the engine dispatcher refuses
    either opt-in combination as a read-only boundary (exit 4) with no artifact."""
    repo = tmp_path / "repo"
    repo.mkdir()
    argv = [sys.executable, "-c", "pass"]
    assert cli._guard_proposer_argv(argv, repo, (), allow_unconfined=True) == argv

    for subcommand in ("run", "resume"):
        _assert_run_not_offered([subcommand, "--help"], capsys)

    legacy = ["run", "--engine", "legacy", "--repo", str(repo), "--worker-cmd", "true",
              "--artifact-out", str(tmp_path / "legacy-a.json"), "--allow-unconfined-proposer"]
    pipeline = ["run", "--repo", str(repo), "--worker-cmd", "true",
                "--artifact-out", str(tmp_path / "pipeline-a.json"), "--allow-unconfined-proposer"]
    for args in (legacy, pipeline):
        rc, err = _engine_main(args, capsys)
        assert rc == 4 and "Hlith Review is read-only" in err
    assert not (tmp_path / "legacy-a.json").exists() and not (tmp_path / "pipeline-a.json").exists()


def test_pipeline_proposer_command_unconfined_opt_in_is_enforced_and_recorded(tmp_path, monkeypatch, capsys):
    """Retargeted (review-only). Was: without the opt-in the inline proposer was refused (4, no artifact); with it the run was recorded as
    unconfined. Now both are refused (4) before the proposer executes, and neither writes an artifact or thread store."""
    repo = tmp_path / "repo"
    _tiny_repo(repo)
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    inline_cmd, marker = _marker_proposer(tmp_path)
    refused_art, allowed_art = tmp_path / "refused.json", tmp_path / "allowed.json"
    for argv in (
        ["run", "--repo", str(repo), "--proposer-command", inline_cmd, "--artifact-out", str(refused_art),
         "--thread-store", str(tmp_path / "store1"), "--target-python", sys.executable],
        ["run", "--engine", "pipeline", "--repo", str(repo), "--proposer-command", inline_cmd, "--allow-unconfined-proposer",
         "--artifact-out", str(allowed_art), "--thread-store", str(tmp_path / "store2"), "--target-python", sys.executable],
    ):
        _assert_run_not_offered(argv, capsys)
        rc, err = _engine_main(argv, capsys)
        assert rc == 4 and "Hlith Review is read-only" in err
    assert not marker.exists(), "the proposer ran although the route is not offered"
    for path in (refused_art, allowed_art, tmp_path / "store1", tmp_path / "store2"):
        assert not path.exists(), path


def test_proposer_guard_refuses_ancestor_of_repo_grant_store_or_host_state(tmp_path, monkeypatch):
    parent = tmp_path / "workspace"
    repo = parent / "target"
    repo.mkdir(parents=True)
    grant = tmp_path / "grants" / "sub"
    grant.mkdir(parents=True)
    store = tmp_path / "stores" / "s1"
    store.mkdir(parents=True)
    state = tmp_path / "state_root" / "nested"
    state.mkdir(parents=True)
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    outside_script = tmp_path / "prop.py"
    outside_script.write_text("print('{}')\n")
    system_python = str(Path(sys.base_prefix) / "bin" / "python3")

    with pytest.raises(RuntimeBoundary, match="contains the target repository"):
        cli._guard_proposer_argv([system_python, str(outside_script), str(parent)], repo, ())
    with pytest.raises(RuntimeBoundary, match="contains a worker-readable grant"):
        cli._guard_proposer_argv([system_python, str(outside_script), str(grant.parent)], repo, (grant,))
    with pytest.raises(RuntimeBoundary, match="contains a worker-readable or protected path"):
        cli._guard_proposer_argv([system_python, str(outside_script), str(store.parent)], repo, (), forbidden=(store,))
    with pytest.raises(RuntimeBoundary, match="contains a worker-readable or protected path"):
        cli._guard_proposer_argv([system_python, str(outside_script), str(state.parent)], repo, ())


def test_command_proposer_output_cap_surfaces_explicit_limit_reason(tmp_path):
    from hlith.agent.proposer import ProposerOutputLimit
    from hlith.agent.supervisor import _safe_proposer_failure

    script = tmp_path / "flood.py"
    script.write_text("import sys; sys.stdin.read(); sys.stdout.write('A' * 4096)\n", encoding="utf-8")
    p = CommandProposer([sys.executable, str(script)], timeout=10.0, max_output=1024)
    with pytest.raises(ProposerOutputLimit) as exc_info:
        p.reply({"turn": 0, "task": "t", "transcript": []})
    msg = _safe_proposer_failure(exc_info.value)
    assert "output" in msg and "1024" in msg and "withheld" not in msg


def test_proposer_own_exit_125_is_not_reported_as_an_output_limit(tmp_path):
    from hlith.agent.proposer import NotConfigured, ProposerOutputLimit

    script = tmp_path / "exit125.py"
    script.write_text("import sys; sys.stdin.read(); sys.stdout.write('{}'); sys.exit(125)\n", encoding="utf-8")
    p = CommandProposer([sys.executable, str(script)], timeout=20.0, max_output=1024)
    with pytest.raises(NotConfigured) as ei:
        p.reply({"turn": 0, "task": "t", "transcript": []})
    assert not isinstance(ei.value, ProposerOutputLimit)
    assert "exited 125" in str(ei.value)


def test_confined_proposer_invalid_utf8_and_stderr_flood(tmp_path):
    from hlith.agent.proposer import NotConfigured

    bad_utf8 = tmp_path / "bad_utf8.py"
    bad_utf8.write_text("import sys; sys.stdin.read(); sys.stdout.buffer.write(b'\\xff\\xfe')\n", encoding="utf-8")
    p_utf8 = CommandProposer([sys.executable, str(bad_utf8)], timeout=20.0)
    with pytest.raises(NotConfigured, match="output is not JSON"):
        p_utf8.reply({"turn": 0, "task": "t", "transcript": []})

    err_flood = tmp_path / "err_flood.py"
    err_flood.write_text(
        "import json, sys; sys.stdin.read(); "
        "sys.stderr.buffer.write(b'E' * (16 * 1024 * 1024)); sys.stderr.buffer.flush(); "
        "print(json.dumps({'tool_calls': [{'name': 'finish', 'summary': 'ok'}]}))\n",
        encoding="utf-8",
    )
    p_err = CommandProposer([sys.executable, str(err_flood)], timeout=20.0)
    out = p_err.reply({"turn": 0, "task": "t", "transcript": []})
    assert out == {"tool_calls": [{"name": "finish", "summary": "ok"}]}


def test_default_pipeline_boundary_refusal_writes_format2_artifact_and_langgraph_store(tmp_path, monkeypatch, capsys):
    """Retargeted (review-only). Was: a failing default-pipeline proposer was refused as agent-runtime-boundary (4) with a format-2
    artifact and a LangGraph store. Now `run` is refused (4) before the proposer, so no artifact and no store exist; the operator's
    repository is unchanged."""
    repo = tmp_path / "repo"
    _tiny_repo(repo)
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    command, marker = _marker_proposer(tmp_path)
    art = tmp_path / "artifact.json"
    argv = ["run", "--repo", str(repo), "--proposer-command", command, "--thread-store", str(tmp_path / "store"),
            "--artifact-out", str(art), "--timeout", "15"]
    _assert_run_not_offered(argv, capsys)
    rc, err = _engine_main(argv, capsys)
    assert rc == 4 and "Hlith Review is read-only" in err
    assert not art.exists() and not (tmp_path / "store").exists() and not marker.exists()
    assert _git(repo, "status", "--porcelain") == ""


