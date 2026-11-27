# SPDX-License-Identifier: Apache-2.0
"""Operator operability, build identity, check actionability, and landing-journal recovery visibility."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from hlith.gate.api import LocalGateService
from hlith.gate.git_write import compute_path_images, head_commit
from hlith.gate.journal import begin_journal
from hlith.hostio.state import LocalHostState
from hlith.operator import cli


def _git(repo: Path, *args: str) -> str:
    cp = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return cp.stdout.strip()


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "pkg/__init__.py").write_text("", encoding="utf-8")
    (repo / "pkg/m.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n",
        encoding="utf-8",
    )
    (repo / "tests/test_m.py").write_text(
        "from pkg.m import add\n\ndef test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    return repo


def test_doctor_reports_build_identity_python_and_clean_journal(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = _make_repo(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "ui"))

    rc = cli.main(["doctor", "--repo", str(repo), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0, payload
    assert payload["envelope"] == "hlith.doctor/1"
    assert payload["build"]["identity"]
    assert payload["build"]["python"] == sys.executable
    assert payload["state_dir"] == str(state.resolve())
    checks = {row["name"]: row for row in payload["checks"]}
    assert checks["Build"]["status"] == "ok"
    assert checks["Landing journal"]["status"] == "ok"
    assert "clean" in checks["Landing journal"]["detail"]

    rc_text = cli.main(["doctor", "--repo", str(repo)])
    out_text = capsys.readouterr().out
    assert rc_text == 0
    assert "Build: ok" in out_text
    assert "Landing journal: ok" in out_text


def test_doctor_flags_pending_interrupted_journal_and_gate_recovers_cleanly(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = _make_repo(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "ui"))

    # Simulate an interrupted landing journal with a dirty touched file before commit.
    base_head = head_commit(repo)
    orig = (repo / "pkg/m.py").read_text(encoding="utf-8")
    (repo / "pkg/m.py").write_text("def add(a: int, b: int) -> int:\n    return b + a\n", encoding="utf-8")
    patch = (_git(repo, "diff") + "\n").encode("utf-8")
    (repo / "pkg/m.py").write_text(orig, encoding="utf-8")

    host_state = LocalHostState(state)
    repo_id = host_state.stable_repo_identity(repo)
    images = compute_path_images(repo, base_head, patch, ["pkg/m.py"])
    begin_journal(
        repo,
        host_state,
        repo_id,
        base_head=base_head,
        paths=["pkg/m.py"],
        patch_sha256=hashlib.sha256(patch).hexdigest(),
        images=images,
    )
    # Simulate partial write left behind when SIGKILL hit before commit.
    (repo / "pkg/m.py").write_text("def add(a: int, b: int) -> int:\n    return b + a\n", encoding="utf-8")

    # Read-only doctor must flag the interrupted journal without mutating anything.
    rc = cli.main(["doctor", "--repo", str(repo), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    checks = {row["name"]: row for row in payload["checks"]}
    assert checks["Landing journal"]["status"] == "problem"
    assert "interrupted landing journal" in checks["Landing journal"]["detail"]
    assert "return b + a" in (repo / "pkg/m.py").read_text(encoding="utf-8")

    # Gate recovery rolls back cleanly to base_head and clears the journal.
    status = LocalGateService(host_state).recover(repo)
    assert status.startswith("recovered:")
    assert (repo / "pkg/m.py").read_text(encoding="utf-8") == orig
    assert _git(repo, "status", "--porcelain") == ""

    # Doctor is clean again after recovery.
    rc_after = cli.main(["doctor", "--repo", str(repo), "--json"])
    payload_after = json.loads(capsys.readouterr().out)
    assert rc_after == 0
    checks_after = {row["name"]: row for row in payload_after["checks"]}
    assert checks_after["Landing journal"]["status"] == "ok"


def test_status_and_history_envelopes_carry_build_and_provenance(tmp_path: Path, monkeypatch, capsys) -> None:
    repo = _make_repo(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "ui"))

    rc = cli.main(["status", "--repo", str(repo), "--json"])
    st = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert st["envelope"] == "hlith.status/1"
    assert st["build"]
    assert st["state_dir"] == str(state.resolve())
    assert "provenance" in st

    rc_h = cli.main(["history", "--repo", str(repo), "--json"])
    hist = json.loads(capsys.readouterr().out)
    assert rc_h == 0
    assert hist["envelope"] == "hlith.history/1"
    assert hist["runs"] == []


def test_doctor_confined_imports_report_missing_dependency(tmp_path, monkeypatch, capsys):
    repo = _make_repo(tmp_path)
    monkeypatch.setenv("HLITH_STATE_DIR", str(tmp_path / "state"))
    rc = cli.main(["doctor", "--repo", str(repo), "--json", "--target-python", sys.executable,
                   "--import", "hlith_dependency_that_is_absent"])
    target = json.loads(capsys.readouterr().out)["target_python"]
    assert rc == 1 and target["selection_source"] == "explicit --target-python"
    assert target["probe"]["version"] == ".".join(map(str, sys.version_info[:3]))
    assert target["probe"]["imports"] == {"pytest": "ok", "hlith_dependency_that_is_absent": "ModuleNotFoundError"}
