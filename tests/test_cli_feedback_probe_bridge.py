# SPDX-License-Identifier: Apache-2.0
"""O3 gap row 3: the default (legacy) ``hlith run`` path must wire the L3 probe bridge itself.

Recorded receipts showed ``hlith: feedback step failed: RuntimeError: probe failed (exit 1) ... PackageNotFoundError:
diff_cover`` on EVERY run: the legacy CLI never registered the bridge, so the post-landing probe could not synthesize
dist-info for a package that reads its own metadata. tests/test_feedback.py masks this with an autouse fixture that
registers the bridge in-process, so this test runs the CLI in a FRESH interpreter (no registration by anyone else).
"""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parents[1] / "src")


def _git(repo: Path, *a: str) -> None:
    subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)


def _repo(tmp: Path, with_metadata_read: bool) -> Path:
    r = tmp / "repo"
    (r / "vsnpkg").mkdir(parents=True)
    (r / "tests").mkdir()
    (r / "pyproject.toml").write_text('[project]\nname = "vsnpkg"\nversion = "1.2.3"\n')
    init = ('from importlib.metadata import version\nVERSION = version("vsnpkg")\n' if with_metadata_read else "")
    (r / "vsnpkg" / "__init__.py").write_text(init)
    (r / "vsnpkg" / "m.py").write_text("def f(x):\n    return x + 1\n")
    (r / "tests" / "test_m.py").write_text("from vsnpkg.m import f\n\n\ndef test_f():\n    assert f(1) == 2\n")
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "o3@example.invalid")
    _git(r, "config", "user.name", "O3")
    _git(r, "add", ".")
    _git(r, "commit", "-q", "-m", "base")
    return r


def _run(tmp: Path, repo: Path) -> subprocess.CompletedProcess:
    wdir = tmp / "w"
    wdir.mkdir()
    w = wdir / "w.py"
    w.write_text("import os, json\np='vsnpkg/m.py'\ns=open(p).read()\n"
                 "open(p,'w').write(s.replace('x + 1','x + 2'))\n"
                 "open(os.environ['HLITH_MANIFEST_DIR']+'/manifest.json','w').write(json.dumps({'paths': {p: ['modify']}}))\n")
    worker = [sys.executable, "-I", str(w)]
    code = ("import sys; sys.path.insert(0, %r)\nfrom hlith.cli import main\n"
            "raise SystemExit(main(['run','--engine','legacy','--repo',%r,'--worker-cmd',%r,'--worker-ro',%r,'--artifact-out',%r,"
            "'--target-python',%r]))" % (SRC, str(repo), shlex.join(worker), str(wdir), str(tmp / "a.json"), sys.executable))
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=600)


@pytest.mark.real
def test_legacy_cli_feedback_probe_runs_on_package_that_reads_its_own_version(tmp_path):
    repo = _repo(tmp_path, with_metadata_read=True)
    cp = _run(tmp_path, repo)
    assert "feedback step failed" not in cp.stderr, cp.stderr[-1500:]
    art = json.loads((tmp_path / "a.json").read_text())
    assert art["outcome"] in {"landed", "refused"}
    # the probe really ran to completion and left a record (x+1 -> x+2 is an observable divergence)
    assert list((repo / ".hlith" / "feedback").glob("fb-*.json")), "post-gate probe wrote no feedback record"


@pytest.mark.real
def test_negative_control_probe_failure_is_only_the_missing_metadata(tmp_path):
    """Control: the same run on a package that does NOT read its own metadata never had the failure (so the failure
    above is the unwired bridge, not the harness)."""
    repo = _repo(tmp_path, with_metadata_read=False)
    cp = _run(tmp_path, repo)
    assert "feedback step failed" not in cp.stderr, cp.stderr[-1500:]

