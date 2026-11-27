# SPDX-License-Identifier: Apache-2.0
"""case: --target-python given as a SYMLINK outside the interpreter's granted prefixes made the confined evaluator
fail to start (the symlink path does not exist in the confined mount namespace) with a reason that hid the cause. The
exec path is now the realpath, only when that lies inside a granted prefix; a path that does not stays refused, named."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from hlith import differential as d

UV = Path.home() / ".local/share/uv/python"
REAL311 = next(iter(sorted(UV.glob("cpython-3.11.*-linux-x86_64-gnu/bin/python3.11"))), None)
needs_py = pytest.mark.skipif(REAL311 is None or not REAL311.exists(), reason="needs the uv python3.11")


@needs_py
def test_symlink_outside_prefix_resolves_to_realpath(tmp_path):
    link = tmp_path / "bin" / "py"
    link.parent.mkdir()
    link.symlink_to(REAL311)
    assert d.resolve_target_python(str(link)) == os.path.realpath(REAL311)  # RED before: no such function
    assert d.resolve_target_python(str(REAL311)) == str(REAL311)  # control: the real path is unchanged


def test_in_prefix_interpreter_is_unchanged_so_a_venv_keeps_its_venv():
    venv_py = str(Path(sys.executable))  # a venv python: a symlink INSIDE its own prefix must not be resolved
    assert d.resolve_target_python(venv_py) == venv_py


def test_unusable_interpreter_is_returned_unchanged_for_the_existing_classification(tmp_path):
    missing = str(tmp_path / "nope" / "python")
    assert d.resolve_target_python(missing) == missing


@needs_py
def test_symlink_whose_realpath_is_outside_every_prefix_stays_refused(tmp_path, monkeypatch):
    link = tmp_path / "py"
    link.symlink_to(REAL311)
    monkeypatch.setattr(d, "_target_prefixes_probe", lambda python: [str(tmp_path / "somewhere-else")])
    with pytest.raises(d.TargetPythonUnreachable, match="not executable under confinement"):
        d.resolve_target_python(str(link))


def _repo(tmp: Path) -> Path:
    r = tmp / "repo"
    (r / "pk").mkdir(parents=True)
    (r / "tests").mkdir()
    (r / "pk" / "__init__.py").write_text("")
    (r / "pk" / "m.py").write_text("def f(x):\n    return x + 1\n")
    (r / "tests" / "test_m.py").write_text("from pk.m import f\n\n\ndef test_f():\n    assert f(1) == 2\n")
    for a in (["init", "-q"], ["config", "user.email", "t@t"], ["config", "user.name", "t"], ["add", "."], ["commit", "-qm", "b"]):
        subprocess.run(["git", "-C", str(r), *a], check=True, capture_output=True)
    return r


def _run(tmp: Path, name: str, target: str):
    repo = _repo(tmp / name)
    (tmp / name / "w").mkdir()
    (tmp / name / "out").mkdir()
    w = tmp / name / "w" / "w.py"
    w.write_text("import os, json\np='pk/m.py'\ns=open(p).read()\nopen(p,'w').write(s.replace('x + 1','x + 2'))\n"
                 "open(os.environ['HLITH_MANIFEST_DIR']+'/manifest.json','w').write(json.dumps({'paths': {p: ['modify']}}))\n")
    out = tmp / name / "out" / "a.json"
    src = str(Path(__file__).resolve().parents[1] / "src")
    code = (f"import sys; sys.path.insert(0, {src!r})\nfrom hlith.cli import main\n"
            f"raise SystemExit(main(['run','--repo',{str(repo)!r},'--worker-cmd',{shlex.join([sys.executable, '-I', str(w)])!r},"
            f"'--worker-ro',{str(tmp / name / 'w')!r},'--artifact-out',{str(out)!r},'--target-python',{target!r}]))")
    cp = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=900)
    art = json.loads(out.read_text())
    diff = next(o for o in art["obligations"] if o["id"].startswith("differential"))
    head = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True).stdout
    return cp.returncode, diff, head, status, (repo / "pk" / "m.py").read_text()


@pytest.mark.real
@needs_py
def test_cli_with_symlinked_target_python_behaves_like_the_resolved_path(tmp_path):
    link = tmp_path / "bin" / "python3.11"
    link.parent.mkdir()
    link.symlink_to(REAL311)
    rc_s, diff_s, head_s, st_s, src_s = _run(tmp_path, "sym", str(link))
    rc_r, diff_r, head_r, st_r, src_r = _run(tmp_path, "real", str(REAL311))
    assert "did not start" not in json.dumps(diff_s), diff_s.get("stop_reason")
    assert (rc_s, diff_s["verdict"]) == (rc_r, diff_r["verdict"]) == (10, "refuted"), (rc_s, diff_s, rc_r, diff_r)
    # the refused run never touches the target tree, symlinked or not
    assert st_s == st_r == "" and src_s == src_r == "def f(x):\n    return x + 1\n"


@pytest.mark.real
def test_cli_nonexistent_target_python_stays_unverified_with_the_existing_reason(tmp_path):
    rc, diff, head, status, src_text = _run(tmp_path, "gone", str(tmp_path / "no" / "python"))
    assert diff["verdict"] == "unverified" and "unusable" in json.dumps(diff), diff
    assert status == "" and src_text == "def f(x):\n    return x + 1\n"


def test_sibling_directory_sharing_a_name_prefix_is_not_inside_the_prefix(tmp_path, monkeypatch):
    """Trap (review): /pref/python3 vs /pref/python3-evil. A link whose realpath is under the -evil sibling must NOT count as
    inside the granted prefix /pref/python3 (component-wise compare, not a string prefix)."""
    pref = tmp_path / "pref" / "python3"
    evil = tmp_path / "pref" / "python3-evil"
    other = tmp_path / "other"
    for p in (pref, evil, other):
        p.mkdir(parents=True)
    (evil / "py").write_text("#!/bin/sh\n")
    link = other / "py"
    link.symlink_to(evil / "py")
    monkeypatch.setattr(d, "_target_prefixes_probe", lambda python: [str(pref)])
    with pytest.raises(d.TargetPythonUnreachable, match="not executable under confinement"):
        d.resolve_target_python(str(link))
    # control: a link whose target really is under the granted prefix resolves
    (pref / "py").write_text("#!/bin/sh\n")
    ok = other / "ok"
    ok.symlink_to(pref / "py")
    assert d.resolve_target_python(str(ok)) == os.path.realpath(pref / "py")
