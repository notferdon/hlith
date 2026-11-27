# SPDX-License-Identifier: Apache-2.0
"""`hlith --version` prints 'hlith <identity>' from the SAME source as the Offer first screen (hlith.operator.identity), exits 0, needs no repository, spawns nothing."""

from __future__ import annotations

import subprocess

import pytest

from hlith.operator import cli, identity


def test_version_prints_identity_exit_zero_without_a_repo_or_process(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)  # not a repository
    monkeypatch.setattr(identity, "build_identity", lambda root=None: "RC_TEST-1234abcd")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("--version must not spawn"))
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("--version must not spawn"))
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out == "hlith RC_TEST-1234abcd\n"


def test_version_default_is_the_real_identity(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out == f"hlith {identity.build_identity()}\n"
