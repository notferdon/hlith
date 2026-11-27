# SPDX-License-Identifier: Apache-2.0
"""Hostile-interpreter confinement tests for target-Python prefix discovery and operator probes."""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from hlith.hostio.interpreter import interpreter_prefixes
from hlith.operator import cli


def _git(repo: Path, *args: str) -> str:
    cp = subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return cp.stdout.strip()


def _make_repo_with_hostile_venv(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    (repo / "tests").mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / ".gitignore").write_text(".venv/\n", encoding="utf-8")
    (repo / "pkg/__init__.py").write_text("", encoding="utf-8")
    (repo / "pkg/m.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    (repo / "tests/test_m.py").write_text("from pkg.m import add\n\ndef test_add():\n    assert add(1, 2) == 3\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")

    canary = tmp_path / "HOST_CANARY_BREACHED"
    venv_dir = repo / ".venv"
    (venv_dir / "bin").mkdir(parents=True)
    (venv_dir / "pyvenv.cfg").write_text("home = /nonexistent\n", encoding="utf-8")
    hostile = venv_dir / "bin" / "python"
    hostile.write_text(
        f"#!/bin/sh\necho PWNED > {canary}\nexit 0\n",
        encoding="utf-8",
    )
    hostile.chmod(hostile.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return repo, hostile, canary


def test_hostile_venv_python_is_never_executed_by_prefix_discovery_doctor_or_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo, hostile, canary = _make_repo_with_hostile_venv(tmp_path)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "ui"))

    # 1. Direct prefix discovery must reject a hostile binary without executing it.
    with pytest.raises(ValueError, match="layout is unknown"):
        interpreter_prefixes(str(hostile))
    assert not canary.exists()

    # 2. Read-only doctor must not execute the hostile binary.
    rc_doc = cli.main(["doctor", "--repo", str(repo), "--json"])
    _ = json.loads(capsys.readouterr().out)
    assert rc_doc == 0
    assert not canary.exists()

    # 3. doctor --probe-target must fail closed and NEVER run the hostile script on host.
    rc_probe = cli.main(["doctor", "--repo", str(repo), "--probe-target", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc_probe == 1
    assert "error" in payload["target_python"]["probe"]
    assert not canary.exists()

    # 4. Headless check targeting the hostile venv must NEVER execute it on host (canary absent).
    (repo / "pkg/m.py").write_text("def add(a: int, b: int) -> int:\n    return b + a\n", encoding="utf-8")
    rc_check = cli.main(["check", "--no-input", "--repo", str(repo), "--json"])
    _ = capsys.readouterr()
    assert rc_check != 0 or not canary.exists()
    assert not canary.exists()


def test_hostile_binary_masquerading_with_fake_stdlib_still_cannot_touch_host_under_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Even if an attacker plants a fake lib/python3.13/os.py beside a hostile bin/python3,
    doctor --probe-target executes it ONLY inside Landlock confinement with read-only grants."""
    repo, hostile, canary = _make_repo_with_hostile_venv(tmp_path)
    fake_stdlib = repo / ".venv" / "lib" / "python3.13"
    fake_stdlib.mkdir(parents=True)
    (fake_stdlib / "os.py").write_text("# decoy\n", encoding="utf-8")
    hostile_py3 = repo / ".venv" / "bin" / "python3"
    hostile_py3.write_text(
        f"#!/bin/sh\necho PWNED > {canary}\nexit 0\n",
        encoding="utf-8",
    )
    hostile_py3.chmod(0o755)
    hostile.unlink()
    hostile.symlink_to(hostile_py3)

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "ui"))

    # Prefix discovery accepts the layout (read-only grants only) without executing anything.
    roots = interpreter_prefixes(str(hostile))
    assert str((repo / ".venv").resolve()) in roots
    assert not canary.exists()

    # Probe runs inside confinement with read-only grants; host write to canary MUST fail.
    rc_probe = cli.main(["doctor", "--repo", str(repo), "--probe-target", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc_probe == 1
    assert "error" in payload["target_python"]["probe"]
    assert not canary.exists()


def test_interpreter_prefixes_rejects_traversal_and_unsafe_venv_roots(tmp_path: Path) -> None:
    # Current interpreter is accepted without executing anything.
    cur = interpreter_prefixes(sys.executable)
    assert sys.base_prefix in cur
    assert sys.prefix in cur

    # Symlinked real virtualenv is accepted with both venv root and base_prefix.
    vdir = tmp_path / "real-venv"
    venv.EnvBuilder(symlinks=True, with_pip=False).create(vdir)
    vpy = vdir / "bin" / "python"
    roots = interpreter_prefixes(str(vpy))
    assert str(vdir.resolve()) in roots
    assert sys.base_prefix in roots

    # Path with '..' traversal that escapes bin/ into a non-python binary is rejected.
    bogus = tmp_path / "bin" / "notpython"
    bogus.parent.mkdir(parents=True)
    bogus.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    bogus.chmod(0o755)
    with pytest.raises(ValueError, match="CPython installation binary"):
        interpreter_prefixes(str(tmp_path / "bin" / ".." / "bin" / "notpython"))

    # Non-existent path raises FileNotFoundError (strict resolve).
    with pytest.raises(OSError):
        interpreter_prefixes(str(tmp_path / "missing" / "bin" / "python"))


def test_doctor_surfaces_declared_unprobed_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    (repo / "pkg").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["numpy>=1.24", "rich"]\n',
        encoding="utf-8",
    )
    (repo / "pkg/__init__.py").write_text("", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    monkeypatch.setenv("HLITH_STATE_DIR", str(state))
    monkeypatch.setenv("HLITH_UI_STATE", str(tmp_path / "ui"))

    rc = cli.main(["doctor", "--repo", str(repo), "--target-python", sys.executable, "--probe-target", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["target_python"]["declared_dependencies"] == ["numpy", "rich"]
    tp_check = {row["name"]: row for row in payload["checks"]}["Target Python"]
    assert "declared deps not probed (--import): numpy, rich" in tp_check["detail"]
    assert "explicit interpreter selected" not in tp_check["detail"]
