"""A host-built claim binds the engine to the bytes the operator reviewed: the argv carries --patch-sha256 / --manifest-sha256 of exactly the files start() writes, and the
engine CLI refuses (exit 4) when change.patch is altered between plan and start (the engine's own check, driven here with the real CLI)."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

from hlith.operator.tui import launch


def _repo(tmp_path):
    r = tmp_path / "proj"
    r.mkdir()
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@e.invalid", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@e.invalid", "PATH": "/usr/bin:/bin"}
    (r / "a.py").write_text("def f(x):\n    return x\n")
    for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "base"]):
        subprocess.run(["git", "-C", str(r), *cmd], check=True, env=env, capture_output=True)
    (r / "a.py").write_text("def f(x):\n    return x + 1\n")
    return r


def _patch(repo):
    return subprocess.run(["git", "-C", str(repo), "diff", "HEAD"], capture_output=True, check=True).stdout


def _flag(argv, name):
    return argv[argv.index(name) + 1]


def test_a_host_built_plan_carries_both_hashes_of_the_bytes_it_will_write(tmp_path, monkeypatch):
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    patch = _patch(repo)
    plan = launch.plan(repo, patch_bytes=patch, manifest_obj={"paths": {"a.py": []}}, base_rev=None, label="t")
    assert _flag(plan.argv, "--patch-sha256") == hashlib.sha256(patch).hexdigest()
    assert _flag(plan.argv, "--manifest-sha256") == hashlib.sha256(plan.manifest_bytes).hexdigest()
    assert json.loads(plan.manifest_bytes) == {"paths": {"a.py": []}}
    assert "--patch-sha256" in plan.display() and hashlib.sha256(patch).hexdigest() in plan.display()  # the argv review covers them


def test_start_writes_nothing_so_no_unreviewed_bytes_can_reach_an_engine(tmp_path, monkeypatch):
    """Was: start() wrote exactly the hashed patch/manifest bytes into the run folder. Hlith Review (product.REVIEW_ONLY): start() is
    unavailable, writes no byte and spawns nothing (Popen is guarded for the start call only; git runs for real in plan())."""
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    plan = launch.plan(repo, patch_bytes=_patch(repo), manifest_obj={"paths": {"a.py": []}}, base_rev=None, label="t")
    with monkeypatch.context() as m:
        m.setattr(launch.subprocess, "Popen", lambda *a, **k: (_ for _ in ()).throw(AssertionError("start() spawned a process")))
        meta = launch.start(plan)
    assert meta["state"] == launch.UNAVAILABLE_STATE and "hlith check" in meta["reason"]
    assert not plan.run_dir.exists(), "start() created the run folder"


def test_a_plan_argv_run_by_hand_is_refused_by_the_review_engine(tmp_path, monkeypatch):
    """Was: the engine refused a patch altered between plan and start (exit 4, sha256 named). In Hlith Review the plan's engine command
    is not offered at all: run by hand it is refused as a read-only boundary (exit 4) before any input is read, so no altered or
    unaltered patch can land through it. The hash-mismatch refusal itself is tested on `hlith check` (tests/test_engine_hash_flags.py)."""
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    plan = launch.plan(repo, patch_bytes=_patch(repo), manifest_obj={"paths": {"a.py": []}}, base_rev=None, label="t")
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout
    env = {**os.environ, "PYTHONPATH": str(Path(launch.__file__).resolve().parents[3])}
    done = subprocess.run(plan.argv, cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120)
    assert done.returncode == 4, (plan.argv, done.returncode, done.stderr[-400:])
    assert "read-only" in done.stderr, done.stderr[-400:]
    assert not plan.run_dir.exists()
    assert subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout == head


def test_every_tui_built_launch_is_a_rehearsal_so_no_sentence_may_claim_a_write_to_the_users_branch(tmp_path, monkeypatch):
    """The fact that makes the fixed sentences true: the TUI argv carries --source-repo (engine_cli: rehearsal = source_repo is not None; the landing is in the CLONE, the user's repository is
    never written), and the clone is not the repository."""
    from hlith.operator.tui import frame

    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "state"))
    repo = _repo(tmp_path)
    plan = launch.plan(repo, patch_bytes=_patch(repo), manifest_obj={"paths": {"a.py": []}}, base_rev=None, label="t")
    assert "--source-repo" in plan.argv and Path(_flag(plan.argv, "--source-repo")) == repo.resolve()
    assert Path(_flag(plan.argv, "--repo")) != repo.resolve() and Path(_flag(plan.argv, "--repo")).name == "clone"
    text = " ".join(" ".join("".join(seg.text for seg in line) for line in frame._disposable(100, sample=False, branch="main")).split())
    assert "rehearsal landing" in text and "commits the checked patch to" not in text and "writes back" not in text
