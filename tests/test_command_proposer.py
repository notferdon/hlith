# SPDX-License-Identifier: Apache-2.0
"""E1 part 2 (review, case): an operator-supplied LOCAL command as a supervisor-side proposer. No model, no credentials, no network."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from hlith import layer1
from hlith.proposer import CommandProposer, NotConfigured
from hlith.runtime import RuntimeBoundary, run_worker

PATCH_A = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-VALUE_A = 1\n+VALUE_A = 10\n"
PATCH_B = "diff --git a/b.py b/b.py\n--- a/b.py\n+++ b/b.py\n@@ -1 +1 @@\n-VALUE_B = 2\n+VALUE_B = 20\n"

# the "operator command": reads the turn on stdin, answers with tool calls chosen by the turn number
CMD = '''
import json, os, sys
turn = json.load(sys.stdin)
if os.environ.get("HLITH_TEST_SECRET"):
    sys.stderr.write("LEAK " + os.environ["HLITH_TEST_SECRET"]); sys.exit(7)
A = %r
B = %r
if turn["turn"] == 0:
    calls = [{"name": "apply_patch", "diff": A}]
else:
    calls = [{"name": "apply_patch", "diff": B}, {"name": "declare", "paths": {"a.py": ["modify"], "b.py": ["modify"]}},
             {"name": "finish", "summary": "done"}]
print(json.dumps({"tool_calls": calls}))
''' % (PATCH_A, PATCH_B)


def _git(repo, *a):
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@t")
    _git(r, "config", "user.name", "t")
    (r / "a.py").write_text("VALUE_A = 1\n")
    (r / "b.py").write_text("VALUE_B = 2\n")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _cmd(tmp_path, body=CMD) -> list[str]:
    f = tmp_path / "operator_proposer.py"
    f.write_text(body)
    return [sys.executable, str(f)]


def test_argv_must_be_a_non_empty_list_without_a_shell():
    for bad in ("echo hi", [], [""], [1]):
        with pytest.raises(ValueError):
            CommandProposer(bad)  # type: ignore[arg-type]


def test_the_command_gets_a_scrubbed_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("HLITH_TEST_SECRET", "s3cr3t-token")  # the command exits 7 if it can see this variable
    out = CommandProposer(_cmd(tmp_path)).reply({"turn": 0, "task": "t", "transcript": []})
    assert out["tool_calls"][0]["name"] == "apply_patch"  # it answered: the variable never reached it


def test_a_failing_commands_stderr_is_never_relayed(tmp_path):
    body = "import sys; sys.stderr.write('Bearer sk-live-123456'); sys.exit(1)"
    with pytest.raises(NotConfigured) as e:
        CommandProposer(_cmd(tmp_path, body)).reply({"turn": 0, "task": "t", "transcript": []})
    assert "sk-live" not in str(e.value) and "Bearer" not in str(e.value) and "exited 1" in str(e.value)


@pytest.mark.parametrize("body,why", [("import sys; sys.exit(3)", "exited 3"), ("print('not json')", "not JSON"),
                                       ("print('x' * 300000)", "output exceeded 262144 byte limit"), ("import time; time.sleep(30)", "did not run")])
def test_command_failures_are_boundaries_not_passes(tmp_path, body, why):
    p = CommandProposer(_cmd(tmp_path, body), timeout=2)
    with pytest.raises(NotConfigured) as e:
        p.reply({"turn": 0, "task": "t", "transcript": []})
    assert why in str(e.value)


def test_a_command_drives_the_checkpointed_two_turn_graph(repo, tmp_path):
    p = CommandProposer(_cmd(tmp_path))
    run = run_worker(repo, [], timeout=120, layer1=True, thread_store=tmp_path / "store", proposer=p)
    assert run.graph.proposer["kind"] == "command" and run.graph.proposer["plumbing_only"] is False and run.graph.proposer["turns"] == 2
    assert sorted(run.graph.interrupt_payload["claimed_paths"]) == ["a.py", "b.py"]
    assert (repo / "a.py").read_text() == "VALUE_A = 1\n"  # the target is only ever read; the edit is in the stage


def test_the_command_route_survives_a_crash_between_turns(repo, tmp_path):
    marker = tmp_path / "crashed-once"
    body = CMD + f'''
'''  # same command; the crash is injected by a wrapper proposer below
    class CrashOnce(CommandProposer):
        def reply(self, turn):
            if turn["turn"] == 1 and not marker.exists():
                marker.write_text("x")
                raise RuntimeError("supervisor crash")
            return super().reply(turn)

    store = tmp_path / "store"
    with pytest.raises(RuntimeBoundary):
        run_worker(repo, [], timeout=120, layer1=True, thread_store=store, proposer=CrashOnce(_cmd(tmp_path, body)))
    (d,) = [x for x in store.iterdir() if x.is_dir()]
    rep = layer1.resume_agent_thread(d.name, store, CommandProposer(_cmd(tmp_path, body)), timeout=120, redo_inflight=True)
    assert rep["resumed_from_turn"] == 1 and rep["reached"] == "propose" and rep["proposer"]["kind"] == "command"
    assert [(t["turn"], t["ok"]) for t in rep["transcript"] if t["tool"] == "apply_patch"] == [(0, True), (1, True)]


def test_worker_cmd_cannot_be_combined_with_a_proposer(repo, tmp_path):
    """--worker-cmd runs inside the confined stage and has no channel to the supervisor: the two routes are exclusive by construction."""
    with pytest.raises(RuntimeBoundary) as e:
        run_worker(repo, ["true"], timeout=60, layer1=True, proposer=CommandProposer(_cmd(tmp_path)))
    assert "replaces the worker command" in str(e.value)


def test_command_runs_in_private_empty_cwd_without_pythonpath(repo, tmp_path, monkeypatch):
    import os

    body = (
        "import json, os\nfrom pathlib import Path\n"
        "cwd = Path.cwd()\n"
        "print(json.dumps({'tool_calls': [], 'cwd': str(cwd), 'empty': not list(cwd.iterdir()), "
        "'private': (cwd.stat().st_mode & 0o077) == 0, 'pythonpath': 'PYTHONPATH' in os.environ, "
        "'home': os.environ.get('HOME'), 'tmpdir': os.environ.get('TMPDIR')}))\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "repo-code"))
    monkeypatch.setenv("TMPDIR", str(repo))  # an operator-controlled TMPDIR must not put proposer cwd in the target
    monkeypatch.chdir(repo)

    result = CommandProposer(_cmd(tmp_path, body), allow_unconfined=True).reply({"turn": 0, "task": "t", "transcript": []})
    assert result["pythonpath"] is False
    assert result["empty"] is True and result["private"] is True
    assert Path(result["cwd"]).resolve() != repo.resolve()
    assert result["tmpdir"] == result["cwd"]
    assert result["home"] == "/nonexistent"


def test_command_child_dies_when_supervisor_is_sigkilled(tmp_path):
    import os
    import signal
    import time

    marker = tmp_path / "proposer-pid"
    script = tmp_path / "sleeping-proposer.py"
    script.write_text(
        "import os, sys, time\n"
        f"open({str(marker)!r}, 'w').write(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    driver = tmp_path / "supervisor.py"
    driver.write_text(
        "import sys\nfrom hlith.proposer import CommandProposer\n"
        "CommandProposer([sys.executable, sys.argv[1], sys.argv[2]], timeout=90, allow_unconfined=True).reply("
        "{'turn': 0, 'task': 't', 'transcript': []})\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    env["TMPDIR"] = str(tmp_path / "tmp")
    Path(env["TMPDIR"]).mkdir()
    supervisor = subprocess.Popen([sys.executable, str(driver), str(script), str(marker)], cwd=tmp_path, env=env)
    child_pid = None
    try:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not marker.exists() and supervisor.poll() is None:
            time.sleep(0.02)
        assert marker.exists(), "proposer did not start"
        child_pid = int(marker.read_text())
        supervisor.send_signal(signal.SIGKILL)
        supervisor.wait(timeout=5)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{child_pid}/stat").read_text().rsplit(")", 1)[1].strip().split()[0]
            except FileNotFoundError:
                break
            if state == "Z":
                break
            time.sleep(0.02)
        else:
            pytest.fail("proposer child survived supervisor SIGKILL")
    finally:
        if supervisor.poll() is None:
            supervisor.kill()
            supervisor.wait(timeout=5)
        if child_pid is not None:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_unconfined_opt_in_is_recorded_in_agent_provenance(repo, tmp_path):
    proposer = CommandProposer(_cmd(tmp_path), allow_unconfined=True)
    result = run_worker(repo, [], timeout=120, layer1=True, thread_store=tmp_path / "store", proposer=proposer)
    assert result.graph.proposer["allow_unconfined"] is True


def test_confined_proposer_next_to_target_repo_cannot_read_sibling_target_canary(tmp_path):
    """review G2 regression: a script in R/prop.py next to R/target must not get R granted read-only."""
    parent = tmp_path / "R"
    target = parent / "target"
    target.mkdir(parents=True)
    canary = target / "canary.txt"
    canary.write_text("CANARY-secret\n")
    prop = parent / "prop.py"
    prop.write_text(
        "import json\nfrom pathlib import Path\n"
        f"p = Path({str(canary)!r})\n"
        "try:\n"
        "    data = p.read_text()\n"
        "    print(json.dumps({'tool_calls': [], 'read': data}))\n"
        "except OSError as e:\n"
        "    print(json.dumps({'tool_calls': [], 'denied': type(e).__name__}))\n"
    )
    out = CommandProposer([sys.executable, str(prop)]).reply({"turn": 0, "task": "t", "transcript": []})
    assert "read" not in out
    assert out.get("denied") in {"PermissionError", "FileNotFoundError"}


def test_confined_proposer_refuses_symlink_repointed_after_construction(tmp_path):
    """review G10 regression: a symlink repointed after validation must fail closed before execution."""
    import pytest
    from hlith.agent.proposer import NotConfigured

    outside = tmp_path / "O"
    outside.mkdir()
    benign = outside / "benign.txt"
    benign.write_text("ok\n")
    link = outside / "link"
    link.symlink_to(benign)

    target = tmp_path / "T"
    target.mkdir()
    (target / "canary.txt").write_text("CANARY-secret\n")

    prop = outside / "prop.py"
    prop.write_text("import json\nprint(json.dumps({'tool_calls': []}))\n")

    proposer = CommandProposer([sys.executable, str(prop), str(link)])
    link.unlink()
    link.symlink_to(target)

    with pytest.raises(NotConfigured, match="TOCTOU"):
        proposer.reply({"turn": 0, "task": "t", "transcript": []})


def test_confined_proposer_refuses_hardlink_inode_swap_after_construction(tmp_path):
    """review T6 regression: replacing a referenced file with a hardlink after validation must fail closed."""
    import os
    import pytest
    from hlith.agent.proposer import NotConfigured

    outside = tmp_path / "O"
    outside.mkdir()
    data = outside / "data.txt"
    data.write_text("v1\n")

    target = tmp_path / "T"
    target.mkdir()
    canary = target / "canary.txt"
    canary.write_text("CANARY-secret\n")

    prop = outside / "prop.py"
    prop.write_text("import json\nprint(json.dumps({'tool_calls': []}))\n")

    proposer = CommandProposer([sys.executable, str(prop), str(data)])
    data.unlink()
    os.link(canary, data)

    with pytest.raises(NotConfigured, match="TOCTOU"):
        proposer.reply({"turn": 0, "task": "t", "transcript": []})


def test_guarded_proposer_refuses_preexisting_hardlink(tmp_path):
    """review T7 regression: a pre-existing hardlinked regular file must be refused at guard and turn time."""
    import os
    import pytest
    from hlith.agent.proposer import NotConfigured
    from hlith.runtime import RuntimeBoundary
    from hlith.operator.engine_cli import _build_guarded_proposer

    outside = tmp_path / "O"
    outside.mkdir()
    target = tmp_path / "T"
    target.mkdir()
    canary = target / "canary.txt"
    canary.write_text("CANARY-secret\n")

    hardlink = outside / "h7.txt"
    os.link(canary, hardlink)

    prop = outside / "prop.py"
    prop.write_text("import json\nprint(json.dumps({'tool_calls': []}))\n")

    with pytest.raises(RuntimeBoundary, match="st_nlink > 1"):
        _build_guarded_proposer([sys.executable, str(prop), str(hardlink)], target, ())

    proposer = CommandProposer([sys.executable, str(prop), str(hardlink)])
    with pytest.raises(NotConfigured, match="st_nlink > 1"):
        proposer.reply({"turn": 0, "task": "t", "transcript": []})

