"""Focused history/receipt identity regressions owned by review."""

from __future__ import annotations
import pytest

import fcntl
import json
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

from hlith.contract.runs import LandingTarget, RunMode, RunReceipt
from hlith.operator import store
from hlith.operator.origin import InputOrigin
from hlith.operator.state import LocalState
from hlith.operator.tui import frame, host, launch, model


ROOT = Path(__file__).resolve().parents[1]
LANDED = ROOT / "docs" / "evidence" / "e1cli" / "sigkill-operator-ba04a0c4" / "between-artifact.json"
REFUSED = ROOT / "docs" / "evidence" / "acceptance" / "R1" / "4-regression-again.json"
OLD_SCHEMA = ROOT / "docs" / "evidence" / "examples" / "b-refusal.json"


EVIDENCE = Path(__file__).resolve().parent.parent / "docs" / "evidence"
pytestmark = pytest.mark.skipif(not EVIDENCE.is_dir(), reason="source-only evidence fixture is not part of the public source snapshot")

def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _repo(path: Path, name: str) -> Path:
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    (path / "marker.txt").write_text(name + " base\n")
    _git(path, "add", "marker.txt")
    _git(path, "-c", "user.name=Hlith Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "base")
    return path.resolve()


def _artifact(path: Path, run_id: str, *, repository_url: str | None = None,
              base_commit: str | None = None, base_tree: str | None = None) -> dict:
    art = json.loads(path.read_text())
    art["run"]["run_id"] = run_id
    if repository_url is not None:
        art["run"]["repository_url"] = repository_url
    if base_commit is not None:
        art["run"]["base_commit_sha"] = base_commit
    if base_tree is not None:
        art["run"]["base_tree_sha256"] = base_tree
    return art


def _write_launch(runs_root: Path, launch_id: str, run_id: str, repo: Path, artifact: dict, started: float) -> Path:
    launch_dir = runs_root / launch_id
    engine_dir = runs_root / run_id
    launch_dir.mkdir(parents=True)
    engine_dir.mkdir()
    (launch_dir / "meta.json").write_text(json.dumps({
        "run_id": launch_id,
        "started": started,
        "source_repo": str(repo.resolve()),
        "label": repo.name,
    }))
    (launch_dir / "rc").write_text(f"{artifact['exit_status']}\n")
    (launch_dir / store.LINK).write_text(json.dumps({"run_id": run_id, "run_dir": str(engine_dir)}))
    (launch_dir / store.ARTIFACT).write_text(json.dumps(artifact))
    return launch_dir


def _write_receipt(run_dir: Path, repo: Path, run_id: str, state: Path) -> None:
    identity = LocalState(state).stable_repo_identity(repo)
    receipt = RunReceipt(run_id, f"inv-{run_id.removeprefix('run-')}", None,
                         RunMode.STANDALONE, LandingTarget.ORIGINAL)
    store.write_receipt(run_dir, receipt, InputOrigin.AGENT_RUN, identity, str(repo.resolve()))
    (run_dir / "rc").write_text("0\n")


def test_open_foreign_artifact_uses_artifact_repo_and_base_identity(tmp_path, capsys):
    cwd_repo = _repo(tmp_path / "cwd-repo", "cwd")
    cwd_head = _git(cwd_repo, "rev-parse", "HEAD")
    foreign_repo = _repo(tmp_path / "foreign-repo", "foreign")
    base = _git(foreign_repo, "rev-parse", "HEAD")
    base_tree = _git(foreign_repo, "rev-parse", "HEAD^{tree}")
    (foreign_repo / "marker.txt").write_text("foreign head\n")
    _git(foreign_repo, "add", "marker.txt")
    _git(foreign_repo, "-c", "user.name=Hlith Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "head")
    foreign_head = _git(foreign_repo, "rev-parse", "HEAD")

    run_id = "run-aaaaaaaaaaaa"
    run_dir = foreign_repo / ".hlith" / "runs" / run_id
    run_dir.mkdir(parents=True)
    art = _artifact(LANDED, run_id, repository_url=str(foreign_repo.resolve()),
                    base_commit=base, base_tree=base_tree)
    assert frame._validation_errors(art) == []
    artifact_path = run_dir / store.ARTIFACT
    artifact_path.write_text(json.dumps(art))
    _write_receipt(run_dir, foreign_repo, run_id, tmp_path / "state")

    rc = host.main(["--artifact", str(artifact_path), "--repo", str(cwd_repo), "--plain"])
    rendered = capsys.readouterr().out

    assert rc == 0
    assert foreign_head[:8] not in rendered
    assert cwd_repo.name not in rendered
    assert str(cwd_repo) not in rendered and cwd_head[:8] not in rendered
    assert foreign_repo.name in rendered
    assert base[:8] in rendered


def test_foreign_run_artifact_is_blocked_when_run_id_is_not_the_launch_link(tmp_path):
    repo = _repo(tmp_path / "repo", "repo")
    runs_root = tmp_path / "state" / "runs"
    minted = "run-bbbbbbbbbbbb"
    copied_from = "run-cccccccccccc"
    launch_dir = _write_launch(runs_root, "launch-dddddddddddd", minted, repo,
                               _artifact(LANDED, copied_from), 100.0)

    rec = launch.result(launch_dir)
    rows = launch.run_rows(tmp_path / "state")

    assert rec is not None and rec.status == "id-mismatch" and not rec.usable
    assert any("does not belong to this launch" in error.lower() for error in rec.errors)
    assert len(rows) == 1 and rows[0]["decision"] is None
    assert "LANDED" not in launch.run_row_text(rows[0])


def test_history_rows_keep_each_repo_and_validated_artifact_decision_together(tmp_path):
    alpha = _repo(tmp_path / "alpha", "alpha")
    beta = _repo(tmp_path / "beta", "beta")
    runs_root = tmp_path / "state" / "runs"
    alpha_id, beta_id = "run-eeeeeeeeeeee", "run-ffffffffffff"
    alpha_art = _artifact(LANDED, alpha_id)
    beta_art = _artifact(REFUSED, beta_id)
    _write_launch(runs_root, "launch-111111111111", alpha_id, alpha, alpha_art, 100.0)
    _write_launch(runs_root, "launch-222222222222", beta_id, beta, beta_art, 200.0)

    rows = launch.run_rows(tmp_path / "state")
    by_repo = {Path(row["repo"]).name: row for row in rows}

    assert [Path(row["repo"]).name for row in rows] == ["beta", "alpha"]
    assert set(by_repo) == {"alpha", "beta"}
    assert by_repo["alpha"]["run_id"] == "launch-111111111111"
    assert by_repo["beta"]["run_id"] == "launch-222222222222"
    target = {"rehearsal": "rehearsal clone", "original": "original repository"}.get(alpha_art["run"].get("landing_target"), "landing target not recorded")
    assert by_repo["alpha"]["decision"] == f"{model.decision(alpha_art)[0]} \u00b7 {target}"  # a LANDED row names where it landed (same words as `hlith history`)
    assert by_repo["beta"]["decision"] == model.decision(beta_art)[0]
    assert "LANDED" in launch.run_row_text(by_repo["alpha"])
    assert "REFUSED" in launch.run_row_text(by_repo["beta"])


def test_history_verdict_escape_returns_to_offer_with_working_repo_identity(tmp_path):
    working_repo = _repo(tmp_path / "working-repo", "working")
    working_head = _git(working_repo, "rev-parse", "HEAD")
    foreign_repo = _repo(tmp_path / "foreign-repo", "foreign")
    foreign_base = _git(foreign_repo, "rev-parse", "HEAD")
    foreign_tree = _git(foreign_repo, "rev-parse", "HEAD^{tree}")
    state_root = tmp_path / "ui-state"
    launch_id = "launch-111111111111"
    run_id = "run-aaaaaaaaaaaa"
    artifact = _artifact(LANDED, run_id, repository_url=str(foreign_repo.resolve()),
                         base_commit=foreign_base, base_tree=foreign_tree)
    assert frame._validation_errors(artifact) == []
    _write_launch(state_root / "runs", launch_id, run_id, foreign_repo, artifact, 100.0)

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            os.dup2(slave, 0)
            os.dup2(slave, 1)
            os.dup2(slave, 2)
            env = {**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor",
                   "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1",
                   "HLITH_UI_STATE": str(state_root), "HLITH_STATE_DIR": str(state_root)}
            os.execve(sys.executable, [sys.executable, "-m", "hlith.operator.tui", "--repo", str(working_repo)], env)
        finally:
            os._exit(127)

    os.close(slave)
    output = bytearray()
    clear = b"\x1b[H\x1b[2J"

    def latest() -> str:
        frame_bytes = bytes(output).rsplit(clear, 1)[-1]
        return re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", frame_bytes).decode("utf-8", "replace")

    def frame_count() -> int:
        return bytes(output).count(clear)

    def screen_has(predicate, timeout: float = 8.0, *, after_frame: int | None = None) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                try:
                    output.extend(os.read(master, 65536))
                except OSError:
                    return False
            if after_frame is not None and frame_count() <= after_frame:
                continue
            if predicate(latest()):
                return True
        return False

    def send_and_wait(data: bytes, predicate) -> str:
        before = frame_count()
        os.write(master, data)
        assert screen_has(predicate, after_frame=before), f"unexpected screen after {data!r}:\n{latest()}"
        return latest()

    try:
        assert screen_has(lambda text: "no check started" in text and working_repo.name in text
                          and working_head[:8] in text)
        offer = latest()
        assert working_repo.name in offer and working_head[:8] in offer

        history = send_and_wait(b"h", lambda text: "RECORDED RUNS" in text and launch_id in text)
        assert foreign_repo.name in history

        verdict = send_and_wait(b"\r", lambda text: "RECORDED RUNS" not in text and "exit 0" in text
                                and "LANDED" in text and foreign_repo.name in text and foreign_base[:8] in text)
        assert foreign_base[:8] in verdict and working_repo.name not in verdict

        returned_history = send_and_wait(b"\x1b", lambda text: "RECORDED RUNS" in text and launch_id in text
                                         and foreign_repo.name in text and "LANDED HELD" not in text)  # the History row itself says 'LANDED · exit 0'; the Verdict headline is what must be gone
        assert foreign_repo.name in returned_history

        offer = send_and_wait(b"\x1b", lambda text: "no check started" in text and working_repo.name in text
                              and working_head[:8] in text and "RECORDED RUNS" not in text)
        assert working_repo.name in offer and working_head[:8] in offer
        assert foreign_repo.name not in offer and foreign_base[:8] not in offer
    finally:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        os.close(master)


def test_interactive_foreign_artifact_uses_artifact_repo_identity(tmp_path):
    cwd_repo = _repo(tmp_path / "cwd-repo", "cwd")
    cwd_head = _git(cwd_repo, "rev-parse", "HEAD")
    foreign_repo = _repo(tmp_path / "foreign-repo", "foreign")
    base = _git(foreign_repo, "rev-parse", "HEAD")
    base_tree = _git(foreign_repo, "rev-parse", "HEAD^{tree}")
    (foreign_repo / "marker.txt").write_text("foreign head\n")
    _git(foreign_repo, "add", "marker.txt")
    _git(foreign_repo, "-c", "user.name=Hlith Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "head")

    run_id = "run-aaaaaaaaaaaa"
    run_dir = foreign_repo / ".hlith" / "runs" / run_id
    run_dir.mkdir(parents=True)
    artifact = _artifact(LANDED, run_id, repository_url=str(foreign_repo.resolve()),
                         base_commit=base, base_tree=base_tree)
    assert frame._validation_errors(artifact) == []
    artifact_path = run_dir / store.ARTIFACT
    artifact_path.write_text(json.dumps(artifact))
    _write_receipt(run_dir, foreign_repo, run_id, tmp_path / "state")

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            os.dup2(slave, 0)
            os.dup2(slave, 1)
            os.dup2(slave, 2)
            env = {**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor",
                   "PYTHONPATH": str(ROOT / "src"), "PYTHONDONTWRITEBYTECODE": "1",
                   "HLITH_UI_STATE": str(tmp_path / "state"), "HLITH_STATE_DIR": str(tmp_path / "state")}
            os.execve(sys.executable, [sys.executable, "-m", "hlith.operator.tui", "--artifact",
                                       str(artifact_path), "--repo", str(cwd_repo)], env)
        finally:
            os._exit(127)

    os.close(slave)
    output = bytearray()
    clear = b"\x1b[H\x1b[2J"

    def latest() -> str:
        frame_bytes = bytes(output).rsplit(clear, 1)[-1]
        return re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", frame_bytes).decode("utf-8", "replace")

    def screen_has(predicate, timeout: float = 8.0, *, after_frame: int | None = None) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                try:
                    output.extend(os.read(master, 65536))
                except OSError:
                    return False
            if after_frame is not None and bytes(output).count(clear) <= after_frame:
                continue
            if predicate(latest()):
                return True
        return False

    try:
        assert screen_has(lambda text: "LANDED" in text and foreign_repo.name in text and base[:8] in text)
        rendered = latest()
        assert foreign_repo.name in rendered and base[:8] in rendered
        assert cwd_repo.name not in rendered
        assert str(cwd_repo) not in rendered and cwd_head[:8] not in rendered
    finally:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        os.close(master)


def test_a_landed_history_row_says_which_run_landed_on_the_original_and_which_only_in_a_rehearsal(tmp_path):
    """TUI behavior: an apply run and its rehearsal both read 'LANDED exit 0'; the row must say where each landed (the recorded landing_target, 'not recorded' when absent)."""
    expected = {"rehearsal": "LANDED \u00b7 rehearsal clone", "original": "LANDED \u00b7 original repository"}  # a valid format-2 record always carries the target
    for i, (target, words) in enumerate(expected.items()):
        repo = _repo(tmp_path / f"r{i}", f"r{i}")
        rid = f"run-{i:012x}"
        art = _artifact(LANDED, rid)
        art["run"]["landing_target"] = target
        _write_launch(tmp_path / f"state{i}" / "runs", f"launch-{i:012x}", rid, repo, art, 100.0 + i)
        rows = launch.run_rows(tmp_path / f"state{i}")
        assert [r["decision"] for r in rows] == [words], (target, rows)
