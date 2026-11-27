"""A pipeline `hlith resume` on a thread parked at its effect interrupt must not pretend that --engine legacy
completes the gate. Without the recorded checkpoint id it refuses, names that id, and writes no verdict.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from effect_park import park_layer1_patch  # noqa: E402

M_PY = "def add_one(x: int) -> int:\n    return x + 1\n"
T_PY = "from m import add_one\n\n\ndef test_add_one():\n    assert add_one(1) == 2\n"


def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True).stdout


@pytest.fixture
def parked(tmp_path, monkeypatch):
    """A real layer-1 thread parked at its effect interrupt (what the E1 demo creates before the SIGKILL)."""
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t")
    _git(repo, "config", "user.name", "t")
    (repo / "m.py").write_text(M_PY)
    (repo / "tests").mkdir()
    (repo / "tests" / "test_m.py").write_text(T_PY)
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "init")
    (repo / "m.py").write_text(M_PY.replace("return x + 1", "return 1 + x"))
    patch = _git(repo, "diff")
    _git(repo, "checkout", "-q", ".")
    store = tmp_path / "store"
    store.mkdir(mode=0o700)
    run = park_layer1_patch(
        repo, store, patch.encode(),
        manifest_bytes=json.dumps({"paths": {"m.py": ["modify"]}}).encode(),
    )
    try:
        yield run.graph.thread_id, store, run.graph.interrupt_checkpoint_id
    finally:
        run.graph.close()


def test_pipeline_resume_of_a_parked_thread_names_the_checkpoint_and_does_not_abandon_it_to_legacy(parked, capsys):
    from hlith.operator import engine_cli

    thread, store, interrupt_id = parked
    before = (store / thread / "meta.json").read_bytes()
    rc = engine_cli.main(["resume", thread, "--thread-store", str(store)])
    out = capsys.readouterr()
    text = out.out + out.err
    assert rc != 0
    assert interrupt_id in text, text
    assert "--checkpoint-id" in text, text
    assert "does not complete this gate" in text, text
    assert "resume it with `hlith resume`" not in text, text
    assert not (store / thread / "verdict.json").exists()
    assert (store / thread / "meta.json").read_bytes() == before
    assert (store / thread / "stage_delta" / "files" / "m.py").is_file()
    assert not any((store / thread / "stage").glob("*.py"))
